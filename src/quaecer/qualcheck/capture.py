# SPDX-License-Identifier: Apache-2.0
"""Recompute capture evidence from its committed units."""

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ._jcs import dumps
from .schema import BASE
from .timeline import Timeline

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
class Scope:
    name: str
    origin: str
    owner: str
    clock: str
    channels: frozenset[str]
    extent: tuple[int, int]
    error: int | None
    state: str
    supports: bool


@dataclass(frozen=True)
class Composed:
    compatibility: str
    faces: tuple[dict[str, Any], ...]
    conflicts: tuple[dict[str, Any], ...]


def _code(
    code: str, sources: set[str], slots: list[str], channel: str | None = None
) -> dict[str, Any]:
    return {
        "code": code,
        "report_ids": sorted(sources),
        "related_ids": sorted(slots),
        "criterion": None,
        "channel": channel,
    }


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


def _erode(parts: list[Scope], margin: int = 0) -> list[Segment]:
    proofs: list[Segment] = []
    clocks = {part.clock for part in parts}
    for clock in clocks:
        members = [p for p in parts if p.clock == clock and p.error is not None]
        levels = sorted({max(margin, p.error) for p in members if p.error is not None})
        for level in levels:
            contiguous = _regions(
                [(*p.extent, {p.name}) for p in members if p.error is not None and p.error <= level]
            )
            proofs.extend((start + level, end - level, ids) for start, end, ids in contiguous)
    return _regions(proofs)


def _parse(
    reports: dict[str, dict[str, Any]],
    selected: dict[str, dict[str, Any]],
    margin: int,
) -> tuple[list[Scope], list[dict[str, Any]], bool]:
    scopes: list[Scope] = []
    diagnostics = []
    identities = set(reports)
    pending = False
    items = 0
    for name in sorted(selected):
        report = reports[name]
        if report["kind"] != "completeness":
            continue
        statement = _range(report["interval"])
        segmented = bool(report["segments"])
        raw = report["segments"] if segmented else [dict(report, id=name)]
        expected = statement[0]
        for section in sorted(raw, key=lambda row: _range(row["interval"])):
            identifier = section["id"]
            if segmented and identifier in identities:
                raise ValueError("committed unit identity is repeated")
            identities.add(identifier)
            start, end = _range(section["interval"])
            if start != expected or not start < end <= statement[1]:
                raise ValueError("committed units must partition their statement")
            expected = end
            entries = section["entries"]
            actual = "sha256:" + hashlib.sha256(dumps(entries)).hexdigest()
            if actual != section["inventory_digest"] or len(entries) != len(
                {e["event_id"] for e in entries}
            ):
                raise ValueError("invalid committed inventory")
            items += len(entries)
            pending |= bool(entries)
            accuracy, state = report["accuracy_us"], report["status"]
            supports = (
                state == "complete"
                and not entries
                and accuracy is not None
                and accuracy <= margin
                and report["identity_scheme"] == BASE + "occurrence/explicit-id"
            )
            scopes.append(
                Scope(
                    identifier,
                    name,
                    report["observer"],
                    report["clock_id"],
                    frozenset(report["channels"]),
                    (start, end),
                    accuracy,
                    state,
                    supports,
                )
            )
            if state == "complete" and not supports:
                pending = True
                diagnostics.append(_code("statement_obligation", {name}, [identifier]))
        if expected != statement[1]:
            raise ValueError("committed units do not cover their statement")
    if len(scopes) > 100 or items > 500:
        raise ValueError("accepted commitment inventory exceeds limits")
    return scopes, diagnostics, pending


def _affected(all_scopes: list[Scope], failed: Scope, channel: str, rule: str) -> set[Pair]:
    if rule == "segment":
        return {(failed.name, channel)}
    affected: set[Pair] = set()
    for row in all_scopes:
        if row.state != "complete":
            continue
        if rule == "statement" and row.origin == failed.origin:
            affected.update((row.name, ch) for ch in row.channels)
        if row.owner == failed.owner:
            if rule == "observer":
                affected.update((row.name, ch) for ch in row.channels)
            elif rule == "observer_channel" and channel in row.channels:
                affected.add((row.name, channel))
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
    events: Timeline,
) -> Composed:
    """Derive capture and omissions from the profile (QUAL-REQ-022 to 025)."""
    scopes, warnings, pending = _parse(reports, selections, policy["scope_margin_us"])
    if not scopes:
        return Composed(events.compatibility, (), ())
    enabled = [scope for scope in scopes if scope.supports]
    rule = policy["defeat_scope"]
    disabled: set[Pair] = set()
    conflicts = []
    counterexamples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incompatible = events.compatibility == "incompatible"
    for channel, lower_time, upper_time, sources in events.groups:
        lower, upper = _point(lower_time), _point(upper_time)
        available = [p for p in enabled if channel in p.channels]
        nominal = _regions([(*p.extent, {p.name}) for p in available])
        if any(a <= lower <= upper < b for a, b, _ in nominal):
            pending = True
        candidates = []
        for part in available:
            start, end = part.extent
            bound = part.error
            assert bound is not None
            if start - bound <= upper and lower < end + bound:
                candidates.append(part)
        if not any(a <= lower <= upper < b for a, b, _ in _erode(candidates)):
            continue
        incompatible = True
        affected: set[Pair] = set()
        for part in candidates:
            affected.update(_affected(scopes, part, channel, rule))
        disabled.update(affected)
        names = sorted(part.name for part in candidates)
        conflicts.append(
            _code(
                "omitted_event",
                set(sources) | {p.origin for p in candidates},
                names,
                channel,
            )
        )
        counterexamples[channel].append(
            {
                "lower": _text(lower),
                "upper": _text(upper),
                "report_ids": sorted(sources),
                "unit_ids": names,
                "defeat_scope": rule,
                "defeated_units": [{"unit": unit, "channel": ch} for unit, ch in sorted(affected)],
            }
        )

    for admitted in enabled:
        alo, ahi = admitted.extent
        by_channel: dict[str, set[str]] = defaultdict(set)
        for competing in scopes:
            if (
                competing.state not in ("incomplete", "disabled")
                or competing.owner != admitted.owner
            ):
                continue
            blo, bhi = competing.extent
            a, b = admitted.error, competing.error
            if a is None or b is None or max(alo + a, blo + b) >= min(ahi - a, bhi - b):
                continue
            for channel in competing.channels & admitted.channels:
                by_channel[channel].add(competing.origin)
        for channel, competitors in by_channel.items():
            disabled |= _affected(scopes, admitted, channel, rule)
            conflicts.append(
                _code(
                    "conflicting_observations",
                    {admitted.origin, *competitors},
                    [admitted.name],
                    channel,
                )
            )

    frames = []
    span = _range(policy["window"])
    history = (_point(policy["history_scope"]["start"]), _point(policy["lock_at"]))
    for channel in sorted(policy["channels"]):
        sources = {p.origin for p in scopes if channel in p.channels}
        pinned = [selections[key] for key in sorted(sources)]
        reasons = [r for r in warnings if sources.intersection(r["report_ids"])]
        reasons += [r for r in conflicts if r["channel"] == channel]
        safe = _erode(
            [p for p in enabled if channel in p.channels and (p.name, channel) not in disabled],
            policy["scope_margin_us"],
        )
        blocks = []
        for item in scopes:
            a, b = item.extent
            if (item.name, channel) in disabled and item.error is not None:
                blocks.append((a - item.error, b + item.error, {item.name}))
        args = (safe, blocks, pinned, reasons, counterexamples[channel])
        frames.append(
            {
                "channel": channel,
                "window": _projection(span, *args),
                "history": _projection(history, *args),
            }
        )
    status = (
        "incompatible"
        if incompatible
        else ("unresolved" if pending or events.compatibility == "unresolved" else "compatible")
    )
    return Composed(status, tuple(frames), tuple(conflicts))
