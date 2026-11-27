# SPDX-License-Identifier: Apache-2.0
"""Recompute capture evidence from its committed units."""

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ._jcs import dumps
from .clock_view import Unit, check, reason

_ZERO = datetime(1, 1, 1, tzinfo=UTC)

type Segment = tuple[int, int, set[str]]
type Pair = tuple[str, str]


def _point(value: str | datetime) -> int:
    time = datetime.fromisoformat(value).astimezone(UTC) if isinstance(value, str) else value
    elapsed = time - _ZERO
    return elapsed.days * 86400000000 + elapsed.seconds * 1000000 + elapsed.microseconds


def _text(value: int) -> str:
    stamp = _ZERO + timedelta(microseconds=value)
    return stamp.isoformat().removesuffix("+00:00") + "Z"


def _range(document: dict[str, str]) -> tuple[int, int]:
    return _point(document["start"]), _point(document["end"])


@dataclass(frozen=True)
class Composed:
    compatibility: str
    faces: tuple[dict[str, Any], ...]
    conflicts: tuple[dict[str, Any], ...]
    violations: tuple[set[str], ...]
    possible_violation: tuple[str, ...] | None
    premise_reports: tuple[str, ...]
    inferred_violation: bool


def _regions(spans: list[Segment]) -> list[Segment]:
    # Sweep grouped boundaries. Adjacent intervals form one connected component.
    starts: dict[int, set[str]] = defaultdict(set)
    changes: dict[int, int] = defaultdict(int)
    for left, right, names in spans:
        if left < right:
            starts[left].update(names)
            changes[left] += 1
            changes[right] -= 1
    active, lower = 0, 0
    basis: set[str] = set()
    result = []
    for point in sorted(changes):
        if active == 0:
            lower = point
            basis = set()
        basis.update(starts[point])
        active += changes[point]
        if active == 0:
            result.append((lower, point, basis))
    return result


def _erode(parts: list[Unit], margin: int = 0) -> list[Segment]:
    proofs: list[Segment] = []
    clocks = {part.clock for part in parts}
    for clock in clocks:
        members = [p for p in parts if p.clock == clock and p.accuracy is not None]
        levels = sorted({max(margin, p.accuracy) for p in members if p.accuracy is not None})
        for level in levels:
            contiguous = _regions(
                [
                    (p.lower, p.upper, {p.id})
                    for p in members
                    if p.accuracy is not None and p.accuracy <= level
                ]
            )
            proofs.extend((start + level, end - level, ids) for start, end, ids in contiguous)
    return _regions(proofs)


def _parse(
    reports: dict[str, dict[str, Any]],
    selected: dict[str, dict[str, Any]],
) -> list[Unit]:
    scopes: list[Unit] = []
    identities = set(reports)
    items = 0
    for name in sorted(selected):
        report = reports[name]
        if report["kind"] != "completeness":
            continue
        low, high = _range(report["interval"])
        segmented = bool(report["segments"])
        raw = report["segments"] if segmented else [report]
        for section in sorted(raw, key=lambda row: _range(row["interval"])):
            identifier = section["id"]
            if segmented and identifier in identities:
                raise ValueError("committed unit identity is repeated")
            identities.add(identifier)
            start, end = _range(section["interval"])
            if start != low or not start < end <= high:
                raise ValueError("committed units must partition their statement")
            low = end
            entries = section["entries"]
            actual = "sha256:" + hashlib.sha256(dumps(entries)).hexdigest()
            if actual != section["inventory_digest"] or len(entries) != len(
                {e["event_id"] for e in entries}
            ):
                raise ValueError("invalid committed inventory")
            items += len(entries)
            scopes.append(
                Unit(
                    identifier,
                    name,
                    report["observer"],
                    report["clock_id"],
                    tuple(report["channels"]),
                    start,
                    end,
                    report["accuracy_us"],
                    report["status"],
                    report["identity_scheme"],
                    tuple(entries),
                )
            )
        if low != high:
            raise ValueError("committed units do not cover their statement")
    if len(scopes) > 100 or items > 500:
        raise ValueError("accepted commitment inventory exceeds limits")
    return scopes


def _affected(all_scopes: list[Unit], failed: Unit, channel: str, rule: str) -> set[Pair]:
    if rule == "segment":
        return {(failed.id, channel)}
    affected: set[Pair] = set()
    for row in all_scopes:
        if row.status != "complete":
            continue
        if rule == "statement" and row.statement == failed.statement:
            affected.update((row.id, ch) for ch in row.channels)
        if row.observer == failed.observer:
            if rule == "observer":
                affected.update((row.id, ch) for ch in row.channels)
            elif rule == "observer_channel" and channel in row.channels:
                affected.add((row.id, channel))
    return affected


def _projection(
    span: tuple[int, int],
    positive: list[Segment],
    exclusions: list[Segment],
    evidence: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    counterexamples: list[dict[str, Any]],
) -> dict[str, Any]:
    left, right = span

    def clipped(regions: list[Segment]) -> list[Segment]:
        return _regions([(max(span[0], a), min(span[1], b), ids) for a, b, ids in regions])

    def frame(parts: list[Segment]) -> list[dict[str, Any]]:
        return [
            {"interval": {"start": _text(start), "end": _text(end)}, "unit_ids": sorted(ids)}
            for start, end, ids in parts
        ]

    positive = clipped(positive)
    gaps = []
    for lower, upper, _ in positive:
        if left < lower:
            gaps.append({"start": _text(left), "end": _text(lower)})
        left = upper
    if left < right:
        gaps.append({"start": _text(left), "end": _text(right)})
    unique = {dumps(row): row for row in warnings}
    return {
        "covered": frame(positive),
        "gaps": gaps,
        "defeated": frame(clipped(exclusions)),
        "statements": evidence,
        "reasons": [unique[key] for key in sorted(unique)],
        "joint_omissions": sorted(counterexamples, key=dumps),
    }


def compose(
    policy: dict[str, Any],
    reports: dict[str, dict[str, Any]],
    selections: dict[str, dict[str, Any]],
) -> Composed:
    """Compose the clock and coverage fragments from caller-selected reports."""
    scopes = _parse(reports, selections)
    named = {unit.id: unit for unit in scopes}
    exact = check(
        policy,
        [reports[key] for key in sorted(selections)],
        {key: pin["digest"] for key, pin in selections.items()},
        scopes,
    )
    violations = tuple(set(group) for group in exact.violations)
    if not scopes:
        return Composed(
            exact.status,
            (),
            exact.conflicts,
            violations,
            exact.possible_violation,
            exact.premise_reports,
            exact.inferred_violation,
        )
    enabled = [unit for unit in scopes if unit.id in exact.eligible]
    rule = policy["defeat_scope"]
    disabled: set[Pair] = set()
    conflicts = list(exact.conflicts)
    counterexamples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for channel, lower, upper, sources, units in exact.omissions:
        parts = [named[key] for key in units]
        affected = set().union(*(_affected(scopes, part, channel, rule) for part in parts))
        disabled.update(affected)
        conflicts.append(
            reason(
                "omitted_event",
                reports=exact.premise_reports,
                related=units,
                channel=channel,
            )
        )
        counterexamples[channel].append(
            {
                "lower": _text(lower),
                "upper": _text(upper),
                "report_ids": list(sources),
                "unit_ids": list(units),
                "defeat_scope": rule,
                "defeated_units": [{"unit": unit, "channel": ch} for unit, ch in sorted(affected)],
            }
        )
    for code, findings in (
        ("capture_challenge", exact.challenges),
        ("conflicting_observations", exact.opposing),
    ):
        for unit, channel, names in findings:
            parent = named[unit]
            disabled.update(_affected(scopes, parent, channel, rule))
            conflicts.append(
                reason(code, reports={parent.statement, *names}, related=[unit], channel=channel)
            )

    frames = []
    span = _range(policy["window"])
    history = (_point(policy["history_scope"]["start"]), _point(policy["lock_at"]))
    for channel in sorted(policy["channels"]):
        statement_ids = {p.statement for p in scopes if channel in p.channels}
        pinned = [selections[key] for key in sorted(statement_ids)]
        reasons = [r for r in exact.reasons if statement_ids.intersection(r["report_ids"])]
        reasons += [r for r in conflicts if r["channel"] == channel]
        safe = _erode(
            [p for p in enabled if channel in p.channels and (p.id, channel) not in disabled],
            policy["scope_margin_us"],
        )
        blocks = []
        for item in scopes:
            a, b = (item.lower, item.upper)
            if (item.id, channel) in disabled and item.accuracy is not None:
                blocks.append((a - item.accuracy, b + item.accuracy, {item.id}))
        args = (safe, blocks, pinned, reasons, counterexamples[channel])
        frames.append(
            {
                "channel": channel,
                "window": _projection(span, *args),
                "history": _projection(history, *args),
            }
        )
    return Composed(
        exact.status,
        tuple(frames),
        tuple(conflicts),
        violations,
        exact.possible_violation,
        exact.premise_reports,
        exact.inferred_violation,
    )
