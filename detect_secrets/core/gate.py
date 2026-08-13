from __future__ import annotations

import re
from typing import Iterable
from typing import List
from typing import Pattern
from typing import Set
from typing import Tuple
from typing import TYPE_CHECKING

from detect_secrets.plugins.keyword import DENYLIST as KEYWORD_DENYLIST

if TYPE_CHECKING:
    from detect_secrets.plugins.base import BasePlugin

# Real precondition for high-entropy candidate extraction (no length
# threshold exists in the real extraction regex).
_ENTROPY_DELIMITER_PATTERN = r'[\'":=]'

# `denylist` is the RegexBasedDetector contract; `multiline_deny_list` is checkov's
# CustomRegexDetector-specific attribute for isMultiline policies with no prerun.
# Read both via duck typing so this module and scan.py never need a checkov import.
_PATTERN_COLLECTION_ATTRS = ('denylist', 'multiline_deny_list')

# Strips named groups so combining patterns that reuse the same group name
# (e.g. two "begin_key" groups) doesn't raise `redefinition of group name`.
_NAMED_GROUP_RE = re.compile(r'\(\?P<[^>]+>')

# A global inline flag (e.g. `(?i)`) is only legal as the very first token
# of a pattern; embedding it inside `(?:...)` raises `re.error`. Converting
# it to the scoped form `(?i:...)` is legal anywhere and matches the same.
_LEADING_GLOBAL_FLAGS_RE = re.compile(r'^\(\?([aiLmsux]+)\)')

# Constructs that require crossing a line boundary -- see module docstring.
_MULTILINE_MARKERS = (r'\n', r'\r', '(?s)')


def _strip_named_groups(pattern: str) -> str:
    return _NAMED_GROUP_RE.sub('(?:', pattern)


def _scope_leading_flags(pattern: str) -> str:
    match = _LEADING_GLOBAL_FLAGS_RE.match(pattern)
    if not match:
        return pattern
    flags = match.group(1)
    rest = pattern[match.end():]
    return f'(?{flags}:{rest})'


def _line_safe_prefix(pattern: str) -> str:
    """
    Cut `pattern` before the first line-crossing construct, backing up
    further out of any unclosed group/character class. Returns '' if no
    safe non-empty prefix exists -- callers must treat that as "cannot be
    reduced," not "matches everything."
    """
    cut_at = len(pattern)
    for marker in _MULTILINE_MARKERS:
        idx = pattern.find(marker)
        if idx > -1:
            cut_at = min(cut_at, idx)
    prefix = pattern[:cut_at]

    # One stack for both '(' groups and '[' classes (in open order), so a
    # bracket nested inside a group backs up past the group too -- e.g.
    # `(?P<x>[A-Za-z\n]{10,})` must drop the whole group, not just `[...]`.
    stack: List[Tuple[str, int]] = []
    in_bracket = False
    i = 0
    n = len(prefix)
    while i < n:
        c = prefix[i]
        if c == '\\':
            i += 2
            continue
        if in_bracket:
            if c == ']':
                in_bracket = False
                stack.pop()
        else:
            if c == '[':
                in_bracket = True
                stack.append(('bracket', i))
            elif c == '(':
                stack.append(('group', i))
            elif c == ')':
                if stack and stack[-1][0] == 'group':
                    stack.pop()
        i += 1

    if stack:
        return prefix[:stack[0][1]]
    return prefix


def _make_combinable(pattern: str) -> str:
    """Reduce an independently-authored pattern to a fragment safely
    embeddable inside a larger `(?:...)` alternation."""
    return _scope_leading_flags(_strip_named_groups(_line_safe_prefix(pattern)))


class Gate:
    """
    A rebuildable, sound line pre-gate.

    `could_contain_secret(line)` returns False only if no currently loaded
    plugin could possibly match that line. Patterns that can't be safely
    combined are checked individually -- see `untriggerable_plugins`.
    """

    def __init__(self) -> None:
        self._combined: Pattern[str] | None = None
        self._standalone: List[Pattern[str]] = []
        self.untriggerable_plugins: Set[str] = set()
        self.trigger_pattern_count = 0

    def build(self, plugins: Iterable[BasePlugin]) -> None:
        """(Re)build the gate from the currently loaded plugin set."""
        fragments: List[str] = [_make_combinable(word) for word in KEYWORD_DENYLIST]
        fragments.append(_ENTROPY_DELIMITER_PATTERN)

        standalone: List[Pattern[str]] = []
        untriggerable: Set[str] = set()
        for plugin in plugins:
            plugin_name = type(plugin).__name__
            for attr_name in _PATTERN_COLLECTION_ATTRS:
                for compiled in getattr(plugin, attr_name, None) or []:
                    combinable = _make_combinable(compiled.pattern)
                    can_combine = combinable and _compiles(f'(?:{combinable})')
                    if not can_combine:
                        standalone.append(compiled)
                        untriggerable.add(plugin_name)
                        continue
                    fragments.append(combinable)

        combined_source = '(?i)(?:' + '|'.join(f'(?:{f})' for f in fragments) + ')'
        try:
            self._combined = re.compile(combined_source)
        except re.error:
            # Defensive fallback: if the union itself fails to compile,
            # don't silently produce a broken gate -- compile each
            # fragment on its own instead.
            self._combined = None
            standalone.extend(re.compile(f'(?i)(?:{f})') for f in fragments)

        self._standalone = standalone
        self.untriggerable_plugins = untriggerable
        self.trigger_pattern_count = len(fragments) + len(standalone)

    def could_contain_secret(self, line: str) -> bool:
        """True if `line` could possibly match some loaded plugin."""
        if self._combined is not None and self._combined.search(line):
            return True
        return any(p.search(line) for p in self._standalone)


def _compiles(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def build_gate(plugins: Iterable[BasePlugin]) -> Gate:
    gate = Gate()
    gate.build(plugins)
    return gate
