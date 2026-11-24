"""
Document-level pre-validation for regex detectors.

`required_literals(pattern)` returns a set of lowercase literals such that every match of
`pattern` contains at least one of them, or None when no such set can be derived. A document that
contains none of the literals (case-insensitively) cannot match the pattern, so the regex can be
skipped for that document. The derivation is conservative: anything it does not understand yields
None, which means "always run".
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Pattern

if sys.version_info >= (3, 11):
    from re import _constants as sre_constants  # type: ignore[attr-defined]
    from re import _parser as sre_parse  # type: ignore[attr-defined]
else:  # pragma: no cover
    import sre_constants
    import sre_parse

MIN_LITERAL_LENGTH = 3

Requirement = Optional[FrozenSet[str]]


def is_enabled(env_var: str) -> bool:
    return os.getenv(env_var, '0') != '0'


def _better(current: Requirement, candidate: Requirement) -> Requirement:
    """Prefer the requirement whose shortest literal is longest (more selective)."""
    if candidate is None:
        return current
    if current is None:
        return candidate
    return candidate if min(map(len, candidate)) > min(map(len, current)) else current


def _usable(literals: Iterable[str]) -> Requirement:
    values = frozenset(literal.lower() for literal in literals)
    if not values or min(map(len, values)) < MIN_LITERAL_LENGTH:
        return None
    return values


def _leading_literal(items: List) -> str:
    """The literal characters an alternative must start with."""
    leading: List[str] = []
    for op, arg in items:
        if op != sre_constants.LITERAL:
            break
        leading.append(chr(arg))
    return ''.join(leading)


def _requirement(items: List) -> Requirement:
    """Best requirement for a sequence of parsed regex items (all of them must match in order)."""
    best: Requirement = None
    run: List[str] = []

    def flush() -> None:
        nonlocal best, run
        if run:
            best = _better(best, _usable([''.join(run)]))
            run = []

    for op, arg in items:
        if op == sre_constants.LITERAL:
            run.append(chr(arg))
            continue
        # The regex parser factors a common prefix out of alternatives
        # (`AKIA|ASIA` -> `A(?:KIA|SIA)`), so remember the literal run in front of a branch and
        # glue it back onto each alternative.
        prefix = ''.join(run)
        flush()
        if op == sre_constants.BRANCH and prefix:
            alternatives = [prefix + _leading_literal(list(branch)) for branch in arg[1]]
            best = _better(best, _usable(alternatives))
        if op == sre_constants.SUBPATTERN:
            best = _better(best, _requirement(list(arg[-1])))
        elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT) or \
                op == getattr(sre_constants, 'POSSESSIVE_REPEAT', None):
            minimum, _, inner = arg
            if minimum >= 1:
                best = _better(best, _requirement(list(inner)))
        elif op == sre_constants.BRANCH:
            branches = [_requirement(list(branch)) for branch in arg[1]]
            known = [branch for branch in branches if branch is not None]
            if branches and len(known) == len(branches):
                best = _better(best, _usable(literal for branch in known for literal in branch))
        elif op == sre_constants.ASSERT:
            _direction, inner = arg
            best = _better(best, _requirement(list(inner)))
        # Anything else (classes, anchors, negative lookarounds, backrefs, ...) breaks the run.
    flush()
    return best


@lru_cache(maxsize=10000)
def required_literals_for_source(pattern: str, flags: int = 0) -> Requirement:
    try:
        parsed = sre_parse.parse(pattern, flags)
    except Exception:
        return None
    try:
        return _requirement(list(parsed.data))
    except Exception:
        return None


def required_literals(pattern: Pattern[str]) -> Requirement:
    # Drop re.UNICODE (0x20), which is implied for str patterns and only adds cache keys.
    return required_literals_for_source(pattern.pattern, pattern.flags & ~0x20)


def could_match(requirement: Requirement, lowered_document: str) -> bool:
    """True if a document (already lowercased) may contain a match of the pattern."""
    if requirement is None:
        return True
    return any(literal in lowered_document for literal in requirement)
