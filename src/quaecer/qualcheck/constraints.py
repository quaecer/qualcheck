# SPDX-License-Identifier: Apache-2.0
"""Check conjunctions and branches of strict rational time constraints."""

from dataclasses import dataclass

type Atom = tuple[int, int, int, bool]
type Clause = tuple[Atom, ...]


class LimitReached(Exception):
    """Search could not finish within the fixed work allowance."""


@dataclass
class Budget:
    """Count relaxations and clause scans in one receiving assessment."""

    remaining: int = 4_000_000

    def debit(self, count: int) -> None:
        self.remaining -= count
        if self.remaining < 0:
            raise LimitReached


def _weight(atom: Atom, scale: int) -> int:
    return atom[2] * scale - int(atom[3])


def _potentials(size: int, atoms: tuple[Atom, ...], cap: Budget) -> list[int] | None:
    # Integer bound weights have exact real feasibility at this scale.
    scale = size + 1
    distances = [0] * size
    edges = [(a[0], a[1], _weight(a, scale)) for a in atoms]
    for _round in range(size):
        cap.debit(len(edges) + 1)
        lowered = False
        for target, origin, limit in edges:
            bound = distances[origin] + limit
            if bound < distances[target]:
                distances[target] = bound
                lowered = True
        if not lowered:
            return distances
    return None


def feasible(size: int, clauses: list[Clause], budget: Budget) -> bool:
    """Decide disjunctive feasibility without rounding strict endpoints.

    >>> feasible(2, [((1, 0, 1, True),), ((0, 1, 0, True),)], Budget())
    True
    >>> feasible(2, [((1, 0, 0, False),), ((0, 1, 0, True),)], Budget())
    False
    """
    if () in clauses:
        return False
    fixed = tuple(row[0] for row in clauses if len(row) == 1)
    choices = [row for row in clauses if len(row) > 1]
    search: list[tuple[Atom, ...]] = [fixed]
    while search:
        branch = search.pop()
        values = _potentials(size, branch, budget)
        if values is None:
            continue
        budget.debit(len(choices) + 1)
        for row in choices:
            if any(
                values[a] - values[b] <= _weight(atom, size + 1)
                for atom in row
                for a, b, _, _ in (atom,)
            ):
                continue
            search.extend((*branch, alternative) for alternative in reversed(row))
            break
        else:
            return True
    return False
