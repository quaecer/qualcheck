# SPDX-License-Identifier: Apache-2.0
"""Reconstruct a bounded assessment from verified source inputs."""

import base64
import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from fractions import Fraction
from typing import Any

from ._jcs import dumps
from .schema import BASE, Catalogue, decode

_SCALAR = {"body", "check", "control", "dependence", "run_status", "selection"}


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(dumps(value)).hexdigest()


def _indexed(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {item["id"]: item for item in items}
    if len(result) != len(items):
        raise ValueError("identifier repeated")
    return result


def _walk(document: Any) -> Iterator[dict[str, Any]]:
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            yield value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def _date(value: str) -> datetime:
    if value[-1] != "Z" and (int(value[-5:-3]) >= 24 or int(value[-2:]) >= 60):
        raise ValueError("unknown offset")
    stamp = datetime.fromisoformat(value)
    return stamp.astimezone(UTC)


def _settings(policy: dict[str, Any], registry: dict[str, Any]) -> None:
    nodes = set(registry["uses"])
    predecessors: dict[str, set[str]] = {name: set() for name in nodes}
    for edge in registry["edges"]:
        if edge["source"] not in nodes or edge["target"] not in nodes:
            raise ValueError("unregistered edge")
        predecessors[edge["target"]].add(edge["source"])
    free: set[str] = set()
    while predecessors:
        open_nodes = {name for name, incoming in predecessors.items() if incoming <= free}
        if not open_nodes:
            raise ValueError("cyclic registry")
        free.update(open_nodes)
        for name in open_nodes:
            del predecessors[name]

    comparison = set()
    applicable = False
    use = policy["use"]["kind"]
    if use not in nodes:
        raise ValueError("unregistered use")
    for rule in _indexed(policy["rules"]).values():
        if set(rule["uses"]) - nodes:
            raise ValueError("unregistered applicability")
        selected = use in rule["uses"]
        applicable |= selected
        operator = rule["operator"]
        if operator == "control" and Fraction(rule["tolerance"]) < 0:
            raise ValueError("negative tolerance")
        if operator == "coverage" and rule["channel"] not in policy["channels"]:
            raise ValueError("unregistered coverage channel")
        if operator == "dependence" and selected:
            endpoints = frozenset((dumps(rule["left"]), dumps(rule["right"])))
            if len(endpoints) != 2:
                raise ValueError("comparison requires two distinct revisions")
            comparison.add(endpoints)
    if not applicable or len(comparison) > 1:
        raise ValueError("invalid policy obligations")
    if _date(policy["history_scope"]["start"]) >= _date(policy["lock_at"]):
        raise ValueError("invalid history bounds")


class _Input:
    def __init__(self, request: dict[str, Any]) -> None:
        policy = self.policy = request["policy"]
        evidence, caller = request["evidence"], request["caller"]
        registry_hash = _hash(request["use_registry"])
        self.policy_digest = _hash(policy)
        common = {
            "policy_digest": self.policy_digest,
            "use": policy["use"]["id"],
            "subject": policy["subject"],
            "implementation": policy["implementation"],
        }
        for part in (evidence, caller):
            if any(part[name] != value for name, value in common.items()):
                raise ValueError("inexact request context")
        if {caller["use_registry_digest"], policy["use_registry_digest"]} != {registry_hash}:
            raise ValueError("inexact registry")
        if evidence["claim"] != policy["use"]["claim"]:
            raise ValueError("inexact claim")
        _settings(policy, request["use_registry"])

        references = _indexed(evidence["references"])
        reports = self.reports = _indexed(evidence["reports"])
        if not references.keys().isdisjoint(reports):
            raise ValueError("ambiguous revision identity")
        for document in (policy, evidence, caller["bodies"]):
            for value in _walk(document):
                if set(value) == {"id", "digest"} and references.get(value["id"]) != value:
                    raise ValueError("unresolved revision pin")
                if set(value) == {"start", "end"} and _date(value["start"]) >= _date(value["end"]):
                    raise ValueError("invalid time interval")
                if value.get("at") is not None:
                    _date(value["at"])
        for report in reports.values():
            if report["kind"] == "selection":
                required = set(_indexed(report["required"]))
                included = set(_indexed(report["included"]))
                omitted = set(_indexed(report["omitted"]))
                if included & omitted or (included | omitted) - required:
                    raise ValueError("inexact selection report")

        selections = self.selections = _indexed(caller["report_pins"])
        for identifier, selected in selections.items():
            if identifier not in reports:
                raise ValueError("selected report is absent")
            row = reports[identifier]
            if (
                _hash(row) != selected["digest"]
                or row["subject"] != common["subject"]
                or row["implementation"] != common["implementation"]
            ):
                raise ValueError("selected report changed")

        self.bodies: dict[bytes, bytes] = {}
        for body in caller["bodies"]:
            symbol = dumps(body["artifact"])
            decoded = base64.b64decode(body["bytes_base64"], validate=True)
            if symbol in self.bodies or base64.b64encode(decoded).decode() != body["bytes_base64"]:
                raise ValueError("invalid body entry")
            self.bodies[symbol] = decoded
        snapshot = {
            "claim": evidence["claim"],
            "subject": evidence["subject"],
            "implementation": evidence["implementation"],
            "use_registry_digest": registry_hash,
            "references": list(dict(sorted(references.items())).values()),
            "reports": list(dict(sorted(selections.items())).values()),
            "bodies": sorted(caller["bodies"], key=lambda body: body["artifact"]["id"]),
        }
        self.view_digest = _hash(snapshot)

    def basis(self, keys: list[str]) -> list[dict[str, Any]]:
        pins = {
            revision["id"]: revision
            for key in keys
            for revision in (self.selections[key], *self.reports[key]["basis"])
        }
        return [pins[key] for key in sorted(pins)]

    def matched(self, rule: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
        operator = rule["operator"]
        for identifier, report in self.reports.items():
            if report["kind"] != operator:
                continue
            if operator in {"check", "control"} and report["criterion"] != rule["criterion"]:
                continue
            if operator == "dependence" and (
                report["dimension"] != rule["dimension"]
                or {dumps(report["left"]), dumps(report["right"])}
                != {dumps(rule["left"]), dumps(rule["right"])}
            ):
                continue
            if operator == "run_status" and report["run"] != rule["run"]:
                continue
            if operator == "body" and report["artifact"] != rule["artifact"]:
                continue
            if operator == "selection" and not any(p in rule["items"] for p in report["required"]):
                continue
            yield identifier, report


def _reason(
    kind: str,
    criterion: str | None,
    reports: set[str] | None = None,
    channel: str | None = None,
    related: str | None = None,
) -> dict[str, Any]:
    return {
        "code": kind,
        "report_ids": sorted(reports or ()),
        "related_ids": [related] if related is not None else [],
        "criterion": criterion,
        "channel": channel,
    }


def _decision(
    rule: dict[str, Any],
    selected: dict[str, dict[str, Any]],
    context: _Input,
) -> tuple[str, set[str]]:
    mode = rule["operator"]
    affirm: set[str] = set()
    deny: set[str] = set()
    if mode == "selection":
        item_status = []
        conflicts: set[str] = set()
        for pin in rule["items"]:
            included, omitted = set(), set()
            for name, report in selected.items():
                if pin in report["included"]:
                    included.add(name)
                if pin in report["omitted"]:
                    omitted.add(name)
            if included and omitted:
                conflicts |= included | omitted
            item_status.append((bool(included), bool(omitted)))
        if (False, True) in item_status:
            return "opposition", conflicts
        if conflicts:
            return "both", conflicts
        return ("support" if all(yes for yes, _ in item_status) else "neither"), set()

    relations = set()
    for name, report in selected.items():
        if mode == "check":
            if report["result"] not in ("pass", "fail"):
                continue
            supports = report["result"] == "pass"
        elif mode == "control":
            if report["observed"] is None or report["unit"] != rule["unit"]:
                continue
            observed, expected = Fraction(report["observed"]), Fraction(rule["expected"])
            supports = (
                expected - Fraction(rule["tolerance"])
                <= observed
                <= (expected + Fraction(rule["tolerance"]))
            )
        elif mode == "dependence":
            if report["relation"] == "unknown":
                continue
            relations.add(report["relation"])
            supports = rule["required"] == "known" or rule["required"] == report["relation"]
        elif mode == "run_status":
            if report["value"] == "unknown":
                continue
            supports = report["value"] == "succeeded"
        else:
            raw = context.bodies.get(dumps(report["artifact"]))
            if raw is None:
                continue
            supports = (
                report["size"] == len(raw)
                and report["raw_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
            )
        (affirm if supports else deny).add(name)
    if (affirm and deny) or len(relations) > 1:
        return "both", affirm | deny
    if affirm:
        return "support", set()
    if deny:
        return "opposition", set()
    return "neither", set()


def derive(request: dict[str, Any]) -> dict[str, Any]:
    """Recompute the result from raw inputs (QUAL-REQ-008 through QUAL-REQ-016)."""
    context = _Input(request)
    policy = context.policy
    rows: list[dict[str, Any]] = []
    issues: dict[bytes, dict[str, Any]] = {}
    dependence = {}
    for rule in sorted(policy["rules"], key=lambda value: value["id"]):
        criterion = rule["id"]
        record: dict[str, Any] = dict(
            criterion=criterion,
            execution="evaluated",
            value="neither",
            outcome="cantTell",
            basis=[],
            reasons=[],
        )
        rows.append(record)
        if policy["use"]["kind"] not in rule["uses"]:
            record.update(execution="not_applicable", outcome="inapplicable")
            continue
        operator = rule["operator"]
        if operator not in _SCALAR:
            record["reasons"] = [
                _reason("clock_unresolved", criterion, channel=rule.get("channel"))
            ]
            continue

        candidates = dict(context.matched(rule))
        accepted = {key: row for key, row in candidates.items() if key in context.selections}
        value, conflict = _decision(rule, accepted, context)
        outcome = {"support": "passed", "opposition": "failed"}.get(value, "cantTell")
        reasons = []
        if conflict:
            issue = _reason("conflicting_observations", criterion, conflict)
            issues[dumps(issue)] = issue
            reasons.append(issue)
        if value == "neither":
            if accepted and all(row.get("state") == "not_run" for row in accepted.values()):
                record["execution"], outcome = "not_run", "untested"
            if operator == "body" and dumps(rule["artifact"]) not in context.bodies:
                reasons.append(_reason("missing_body", None, related=rule["artifact"]["id"]))
            if removed := candidates.keys() - accepted.keys():
                reasons.append(_reason("report_not_accepted", criterion, removed))
            if not reasons and outcome != "untested":
                reasons.append(_reason("unavailable_report", criterion))
        record.update(
            value=value,
            outcome=outcome,
            basis=context.basis(list(accepted)),
            reasons=sorted(reasons, key=dumps),
        )
        if operator == "dependence":
            key = rule["dimension"]
            relation = {row["relation"] for row in accepted.values()} - {"unknown"}
            comparison = sorted((rule["left"], rule["right"]), key=lambda pin: pin["id"])
            dependence[key] = {
                "dimension": key,
                "comparison": dict(zip(("left", "right"), comparison, strict=True)),
                "relation": next(iter(relation)) if len(relation) == 1 else "unknown",
                "reports": [context.selections[name] for name in sorted(accepted)],
                "basis": record["basis"],
            }

    has_timing = any(context.reports[key]["kind"] not in _SCALAR for key in context.selections)
    results = {row["outcome"] for row in rows}
    consistency = "inconsistent" if issues else "unresolved" if has_timing else "consistent"
    qualification = "prerequisites_unresolved"
    if "failed" in results:
        qualification = "prerequisites_failed"
    elif consistency == "consistent" and results <= {"passed", "inapplicable"}:
        qualification = "prerequisites_satisfied"
    return {
        "profile": BASE + "result",
        "policy_digest": context.policy_digest,
        "view_digest": context.view_digest,
        "use_registry_digest": policy["use_registry_digest"],
        "use": policy["use"]["id"],
        "subject": policy["subject"],
        "implementation": policy["implementation"],
        "clock_compatibility": ("unresolved" if has_timing else "compatible"),
        "consistency": consistency,
        "qualification": qualification,
        "authorization": "not_granted",
        "findings": rows,
        "coverage": [],
        "dependence": [dependence[key] for key in sorted(dependence)],
        "inconsistencies": [issues[key] for key in sorted(issues)],
        "transfers": [],
        "resolving_sets": {"status": "not_run", "sets": [], "search_bound_reached": None},
    }


def receive(raw: bytes, catalogue: Catalogue) -> dict[str, Any]:
    """Evaluate or verify one specified input and result (QUAL-REQ-017)."""
    try:
        message = decode(raw)
        if not isinstance(message, dict):
            return {"status": "invalid"}
        if message.get("profile") == BASE + "verification-request":
            if set(message) != {"profile", "request", "result"}:
                return {"status": "invalid"}
            request, supplied = message["request"], message["result"]
            if (
                not catalogue.accepts("request", request)
                or request["operation"] != "assess"
                or not catalogue.accepts("result", supplied)
            ):
                return {"status": "invalid"}
            return {
                "status": "verified" if dumps(derive(request)) == dumps(supplied) else "mismatch"
            }
        if not catalogue.accepts("request", message):
            return {"status": "invalid"}
        if message["operation"] == "validate":
            return {"status": "valid"}
        return derive(message)
    except (ValueError, OverflowError, RecursionError):
        return {"status": "invalid"}
