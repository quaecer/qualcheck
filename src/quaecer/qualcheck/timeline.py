# SPDX-License-Identifier: Apache-2.0
"""Resolve occurrence components and check their declared true-time bounds."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

type Site = tuple[str, str, str]
type Report = dict[str, Any]


@dataclass(frozen=True)
class Timeline:
    compatibility: str
    conflicts: tuple[tuple[str, set[str], str | None], ...]
    violations: tuple[set[str], ...]
    groups: tuple[tuple[str, datetime, datetime, set[str]], ...]


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text).astimezone(UTC)


def _site(item: Report) -> Site:
    return (item["resource"]["id"], item["resource"]["digest"], item["channel"])


def _range(item: Report) -> tuple[datetime, datetime] | None:
    before = item["uncertainty_before_us"]
    after = item["uncertainty_after_us"]
    if item["at"] is None or before is None or after is None:
        return None
    try:
        time = _time(item["at"])
        return time - timedelta(microseconds=before), time + timedelta(microseconds=after)
    except OverflowError:
        return None


def timeline(policy: dict[str, Any], selected: list[Report]) -> Timeline:
    """Reconstruct the exposure fragment without trusting result timing fields."""
    events = {row["id"]: row for row in selected if row["kind"] == "exposure"}
    uncertain = any(
        row["kind"] in {"capture_challenge", "channel_scope_challenge"} for row in selected
    )
    adjacency: dict[str, set[str]] = {key: set() for key in events}
    occurrences: dict[tuple[Site, str], list[str]] = defaultdict(list)
    conflicts: list[tuple[str, set[str], str | None]] = []
    for name, row in events.items():
        scope = _site(row)
        if row["identity_scheme"] is None or row["occurrence_id"] is None:
            uncertain = True
        else:
            occurrences[scope, row["occurrence_id"]].append(name)
        for alias in row["same_as"]:
            if alias not in events:
                uncertain = True
            elif _site(events[alias]) != scope:
                uncertain = True
                conflicts.append(("conflicting_observations", {name, alias}, None))
            else:
                adjacency[name].add(alias)
                adjacency[alias].add(name)
    for members in occurrences.values():
        first, *others = members
        for node in others:
            adjacency[first].add(node)
            adjacency[node].add(first)

    h0, lock = _time(policy["history_scope"]["start"]), _time(policy["lock_at"])
    forbidden = {(pin["id"], pin["digest"]) for pin in policy["forbidden"]}
    violations: list[set[str]] = []
    groups: list[tuple[str, datetime, datetime, set[str]]] = []
    incompatible = False
    remaining = set(events)
    while remaining:
        first = remaining.pop()
        component = {first}
        frontier = [first]
        while frontier:
            following = adjacency[frontier.pop()] & remaining
            remaining -= following
            component |= following
            frontier.extend(following)

        resource, digest, channel = _site(events[first])
        in_policy = (resource, digest) in forbidden and channel in policy["channels"]
        known = {}
        for node in component:
            bounds = _range(events[node])
            if bounds is None:
                uncertain = True
            else:
                known[node] = bounds
        if not known:
            continue
        latest = max(pair[0] for pair in known.values())
        earliest = min(pair[1] for pair in known.values())
        if latest > earliest:
            incompatible = True
            conflicts.append(("clock_incompatible", set(known), channel))
            if in_policy:
                violations.extend(
                    {node} for node, (left, right) in known.items() if h0 <= left <= right < lock
                )
        else:
            groups.append((channel, latest, earliest, component))
            if in_policy and h0 <= latest <= earliest < lock:
                violations.append(component)
    status = "incompatible" if incompatible else "unresolved" if uncertain else "compatible"
    return Timeline(status, tuple(conflicts), tuple(violations), tuple(groups))
