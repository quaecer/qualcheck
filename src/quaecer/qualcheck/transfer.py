# SPDX-License-Identifier: Apache-2.0
"""Verify the applicability and exact inputs of a transferred criterion."""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from fractions import Fraction
from typing import Any

from ._jcs import dumps
from .schema import BASE


def _stamp(value: str) -> str:
    return datetime.fromisoformat(value).astimezone(UTC).isoformat()


def _instance(rule: dict[str, Any], policy: dict[str, Any]) -> bytes:
    operator = rule["operator"]
    fields = {k: v for k, v in rule.items() if k not in ("id", "uses")}
    if operator == "dependence":
        fields["left"], fields["right"] = sorted([rule["left"], rule["right"]], key=dumps)
    elif operator == "control":
        fields["expected"] = str(Fraction(rule["expected"]))
        fields["tolerance"] = str(Fraction(rule["tolerance"]))
    elif operator == "selection":
        fields["items"] = sorted(rule["items"], key=dumps)
    options: dict[str, Any] = {"conflict_policy": policy["conflict_policy"]}
    if operator == "coverage":
        options["window"] = {k: _stamp(v) for k, v in policy["window"].items()}
    elif operator == "no_prelock_exposure":
        options |= {
            "start": _stamp(policy["history_scope"]["start"]),
            "lock_at": _stamp(policy["lock_at"]),
            "channels": sorted(policy["channels"]),
            "forbidden": sorted(policy["forbidden"], key=dumps),
        }
    if operator in ("coverage", "no_prelock_exposure"):
        for name in ("scope_margin_us", "defeat_scope"):
            options[name] = policy[name]
    return dumps(dict(profile=BASE + "criterion-instance", predicate=fields, settings=options))


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def reconstruct(
    envelope: dict[str, Any],
    evaluate: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Re-assess each side and reconstruct the transfer certificate."""
    source_req, target_req = envelope["source"], envelope["target"]
    source, target = evaluate(source_req), evaluate(target_req)
    if source["view_digest"] != target["view_digest"]:
        raise ValueError("source and target views differ")
    ps, pt = source_req["policy"], target_req["policy"]
    origin, destination = ps["use"], pt["use"]
    if origin["id"] == destination["id"] and origin != destination:
        raise ValueError("use binding is ambiguous")
    edges = target_req["use_registry"]["edges"]
    reachable = {destination["kind"]}
    while True:
        extension = {edge["source"] for edge in edges if edge["target"] in reachable} - reachable
        if not extension:
            break
        reachable.update(extension)
    if origin["kind"] not in reachable:
        raise ValueError("the registry does not admit this transfer")
    for outcome in (source, target):
        if outcome["consistency"] != "consistent" or outcome["clock_compatibility"] != "compatible":
            return target

    by_criterion = {rule["id"]: _instance(rule, ps) for rule in ps["rules"]}
    outcomes: dict[bytes, dict[str, Any]] = {}
    for finding in source["findings"]:
        if finding["execution"] == "evaluated" and finding["outcome"] in ("passed", "failed"):
            outcomes.setdefault(by_criterion[finding["criterion"]], finding)
    target_rules = {rule["id"]: rule for rule in pt["rules"]}
    certificates = []
    for row in target["findings"]:
        name = row["criterion"]
        instance = _instance(target_rules[name], pt)
        candidate = outcomes.get(instance)
        if (
            row["execution"] != "evaluated"
            or candidate is None
            or any(row[key] != candidate[key] for key in ("value", "outcome"))
        ):
            continue
        row.update(
            basis=candidate["basis"],
            value=candidate["value"],
            outcome=candidate["outcome"],
            reasons=sorted(
                [
                    note | {"criterion": name} if note["criterion"] is not None else note
                    for note in candidate["reasons"]
                ],
                key=dumps,
            ),
        )
        certificates.append(
            dict(
                source_use=source["use"],
                target_use=target["use"],
                source_policy_digest=source["policy_digest"],
                target_policy_digest=target["policy_digest"],
                use_registry_digest=target["use_registry_digest"],
                view_digest=target["view_digest"],
                source_criterion=candidate["criterion"],
                target_criterion=name,
                criterion_digest=_sha(instance),
                source_finding_digest=_sha(dumps(candidate)),
            )
        )
    statuses = {finding["outcome"] for finding in target["findings"]}
    gate = "unresolved"
    if "failed" in statuses:
        gate = "failed"
    elif statuses <= {"passed", "inapplicable"}:
        gate = "satisfied"
    target.update(qualification="prerequisites_" + gate, transfers=certificates)
    return target
