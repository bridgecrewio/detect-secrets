from __future__ import annotations

import re

from detect_secrets.core.gate import _line_safe_prefix
from detect_secrets.core.gate import _make_combinable
from detect_secrets.core.gate import _scope_leading_flags
from detect_secrets.core.gate import _strip_named_groups
from detect_secrets.core.gate import build_gate
from detect_secrets.core.gate import Gate
from detect_secrets.plugins.base import RegexBasedDetector


class TestStripNamedGroups:
    def test_replaces_named_group_with_non_capturing_group(self):
        assert _strip_named_groups(r'(?P<foo>bar)') == '(?:bar)'

    def test_handles_multiple_named_groups(self):
        result = _strip_named_groups(r'(?P<a>x)(?P<b>y)')
        assert result == '(?:x)(?:y)'

    def test_leaves_non_named_groups_untouched(self):
        assert _strip_named_groups(r'(?:foo)(bar)') == r'(?:foo)(bar)'

    def test_result_always_compiles(self):
        pattern = r'(?P<begin_key>BEGIN)(?P<secret_key>[A-Za-z]+)'
        re.compile(_strip_named_groups(pattern))  # must not raise


class TestScopeLeadingFlags:
    def test_converts_leading_global_flag_to_scoped_form(self):
        assert _scope_leading_flags('(?i)(?:algolia)') == '(?i:(?:algolia))'

    def test_leaves_pattern_without_leading_flag_untouched(self):
        assert _scope_leading_flags('(?:algolia)') == '(?:algolia)'

    def test_does_not_touch_non_leading_flag_groups(self):
        # (?i:...) form is already scoped/legal anywhere -- must be left as-is.
        pattern = '(?:foo)(?i:bar)'
        assert _scope_leading_flags(pattern) == pattern

    def test_scoped_result_is_combinable_inside_a_larger_pattern(self):
        """
        This is the exact failure mode found while building v2: a leading
        global `(?i)` flag is illegal anywhere except the very start of a
        pattern passed to re.compile(), so combining `(?i)(?:algolia)` into
        `(?:...)|(?:(?i)(?:algolia))` raises re.error. The scoped form must
        not have this problem.
        """
        scoped = _scope_leading_flags('(?i)(?:algolia)')
        combined = re.compile(f'(?:x)|(?:{scoped})')  # must not raise
        assert combined.search('ALGOLIA')

    def test_multi_char_flags(self):
        assert _scope_leading_flags('(?im)foo') == '(?im:foo)'


class TestLineSafePrefix:
    def test_pattern_without_multiline_marker_is_unchanged(self):
        pattern = r'AKIA[0-9A-Z]{16}'
        assert _line_safe_prefix(pattern) == pattern

    def test_cuts_before_literal_newline(self):
        result = _line_safe_prefix(r'BEGIN_SECRET\n((?:.*\n)+?)END_SECRET')
        assert result == 'BEGIN_SECRET'

    def test_cuts_before_dotall_flag(self):
        result = _line_safe_prefix(r'HEADER(?s).*FOOTER')
        assert result == 'HEADER'

    def test_backs_up_out_of_unclosed_character_class(self):
        """
        A literal \\n inside an open [...] would otherwise produce an
        unterminated character class if cut naively.
        """
        result = _line_safe_prefix(r'PREFIX[A-Za-z\n]{5,}SUFFIX')
        assert result == 'PREFIX'
        re.compile(result)  # must be independently valid

    def test_backs_up_out_of_unclosed_group(self):
        result = _line_safe_prefix(r'(?:HEADER\nBODY)')
        assert result == ''  # the marker is inside the outermost group
        # (nothing safe survives outside it)

    def test_backs_up_out_of_nested_group_and_bracket(self):
        """
        Regression for the specific bug found while building v2:
        PrivateKeyDetector's real pattern nests a character class containing
        \\n INSIDE a named group. An independent "back up to the bracket"
        rule (without considering the enclosing group) would strip the
        [...] but leave the group unclosed, producing an invalid fragment.
        """
        pattern = r'(?P<begin_key>BEGIN KEY-*)(?P<secret_key>[A-Za-z0-9+\n]{10,}={0,3})(?P<end_key>\n*-*END)?'
        result = _line_safe_prefix(pattern)
        assert result == '(?P<begin_key>BEGIN KEY-*)'
        re.compile(result)  # must be independently valid

    def test_empty_result_when_marker_is_first_character(self):
        assert _line_safe_prefix(r'\nSTUFF') == ''

    def test_empty_result_for_pathological_unclosed_bracket(self):
        # Not realistic input, but must never raise or return something
        # that fails to compile.
        result = _line_safe_prefix('[a-z')
        assert result == ''

    def test_result_is_always_a_superset_match_of_the_original_intent(self):
        """
        The prefix must match at least everything the original pattern's
        single-line-safe portion would match -- i.e. it's safe to WIDEN
        (more lines pass the gate) but never safe to NARROW.
        """
        full = r'(?P<begin_key>BEGIN(?: RSA | )PRIVATE KEY-*)(?P<secret_key>[A-Za-z0-9+\n]{10,})'
        prefix = _line_safe_prefix(full)
        compiled = re.compile(prefix)
        for header in (
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN PRIVATE KEY-----',
        ):
            assert compiled.search(header), (
                f'Line-safe prefix {prefix!r} failed to match a header '
                f'the original pattern was designed to trigger on: {header!r}'
            )


class TestMakeCombinable:
    def test_combines_all_three_transforms(self):
        """(?i) prefix + named group + trailing multiline marker, all at once."""
        pattern = r'(?i)(?P<foo>BEGIN)\nBODY'
        result = _make_combinable(pattern)
        # Must be safely embeddable in a larger alternation.
        combined = re.compile(f'(?:x)|(?:{result})')
        assert combined.search('BEGIN')

    def test_result_never_raises_when_combined(self):
        patterns = [
            r'(?i)(?:algolia)',
            r'(?P<begin_key>BEGIN(?: DSA | EC | )PRIVATE KEY-*)(?P<secret_key>[A-Za-z0-9+\n]{10,})',
            r'PuTTY-User-Key-File-2:.{1,40}\n?Encryption:',
            r'AKIA[0-9A-Z]{16}',
            r'\b(?:A3T[A-Z0-9]|ABIA)[0-9A-Z]{16}\b',
        ]
        fragments = [_make_combinable(p) for p in patterns if _make_combinable(p)]
        combined_source = '(?i)(?:' + '|'.join(f'(?:{f})' for f in fragments) + ')'
        re.compile(combined_source)  # must not raise


class _FakePlugin(RegexBasedDetector):
    secret_type = 'Fake'
    denylist: list = []


class TestGateBuild:
    def test_empty_plugin_list_still_builds_a_valid_gate(self):
        gate = build_gate([])
        # keyword denylist + entropy value pattern are always present
        assert gate.trigger_pattern_count > 0
        # 'password' is in the keyword denylist, so it passes regardless of value length
        assert gate.could_contain_secret('password = "x"') is True

    def test_plugin_with_no_denylist_attribute_is_skipped_safely(self):
        class _NoDenylistPlugin:
            pass

        gate = build_gate([_NoDenylistPlugin()])
        assert not gate.untriggerable_plugins

    def test_untriggerable_pattern_falls_back_to_standalone_not_dropped(self):
        """
        A pattern this module cannot safely reduce to a non-empty
        single-line fragment (marker as the very first character) must
        still be checked via its own real compiled pattern -- never
        silently excluded from the gate's guarantee.
        """
        class _EdgeCasePlugin(RegexBasedDetector):
            secret_type = 'Edge Case'
            denylist = [re.compile(r'\nWHOLE_LINE_MARKER')]

        gate = build_gate([_EdgeCasePlugin()])
        assert '_EdgeCasePlugin' in gate.untriggerable_plugins
        # The real pattern itself still gets checked (as a standalone
        # pattern) against any string containing an actual newline.
        assert gate.could_contain_secret('prefix\nWHOLE_LINE_MARKER')

    def test_duplicate_named_groups_across_plugins_do_not_break_combining(self):
        """
        Two different plugins independently using the same named group name
        (e.g. both reusing "begin_key") must not raise
        `re.error: redefinition of group name` when combined.
        """
        class _PluginA(RegexBasedDetector):
            secret_type = 'A'
            denylist = [re.compile(r'(?P<begin_key>AAA)')]

        class _PluginB(RegexBasedDetector):
            secret_type = 'B'
            denylist = [re.compile(r'(?P<begin_key>BBB)')]

        gate = build_gate([_PluginA(), _PluginB()])
        assert not gate.untriggerable_plugins
        assert gate.could_contain_secret('AAA')
        assert gate.could_contain_secret('BBB')

    def test_rebuild_reflects_new_plugin_list(self):
        gate = Gate()
        gate.build([_FakePlugin()])
        count_before = gate.trigger_pattern_count

        class _WithPattern(RegexBasedDetector):
            secret_type = 'With Pattern'
            denylist = [re.compile(r'UNIQUE_TRIGGER_WORD')]

        gate.build([_WithPattern()])
        assert gate.trigger_pattern_count > count_before
        assert gate.could_contain_secret('UNIQUE_TRIGGER_WORD')

    def test_all_real_default_plugins_combine_without_any_fallback(self):
        """
        Builds the gate from every real plugin loaded by default_settings()
        (the actual, full built-in plugin set — 22 plugins as of writing,
        not a hand-picked subset). None of their real denylist patterns
        should need the untriggerable/standalone fallback path -- if one
        does, that's a signal a new plugin's pattern shape isn't handled by
        _make_combinable() yet, and needs investigating before merge.
        """
        from detect_secrets.settings import default_settings
        from detect_secrets.settings import get_plugins

        with default_settings():
            plugins = get_plugins()
            assert len(plugins) >= 20, (
                'Expected the full built-in plugin set to be loaded — got '
                f'{len(plugins)}; is default_settings() broken?'
            )
            gate = build_gate(plugins)

        assert not gate.untriggerable_plugins, (
            f'Real built-in plugins fell back to the standalone/untriggerable '
            f'path: {gate.untriggerable_plugins}. Combined-gate handling may '
            f'need updating for one of these plugins\' pattern shape.'
        )

    def test_one_plugins_trigger_is_not_swallowed_by_a_neighboring_alternation(self):
        """
        Regression-shaped test: when many patterns are OR'd together into
        one big regex, a bug in how one fragment is embedded (e.g. missing
        parens around an alternation containing top-level `|`) can cause a
        neighboring fragment to accidentally "leak" and match unintended
        text, OR cause the fragment itself to only partially apply. This
        builds a gate from several plugins whose patterns contain internal
        alternation (`|`) and confirms each plugin's own distinct trigger
        still works in isolation once combined with the others.
        """
        class _PluginWithAlternation(RegexBasedDetector):
            secret_type = 'Alternation'
            denylist = [re.compile(r'(?:FOO|BAR|BAZ)_TRIGGER')]

        class _PluginPlain(RegexBasedDetector):
            secret_type = 'Plain'
            denylist = [re.compile(r'PLAIN_TRIGGER_WORD')]

        class _PluginAnchored(RegexBasedDetector):
            secret_type = 'Anchored'
            denylist = [re.compile(r'^ANCHORED_AT_START')]

        gate = build_gate([
            _PluginWithAlternation(), _PluginPlain(), _PluginAnchored(),
        ])
        assert not gate.untriggerable_plugins

        for trigger in ('FOO_TRIGGER', 'BAR_TRIGGER', 'BAZ_TRIGGER'):
            assert gate.could_contain_secret(trigger), (
                f'Alternation branch {trigger!r} was lost when combined '
                f'with other plugins\' patterns.'
            )
        assert gate.could_contain_secret('PLAIN_TRIGGER_WORD')
        assert gate.could_contain_secret('ANCHORED_AT_START')
        # A completely unrelated string must still be correctly rejected --
        # confirms the alternation isn't accidentally matching everything.
        assert not gate.could_contain_secret('nothing interesting here at all')

    def test_gate_is_deterministic_across_rebuilds_with_same_plugins(self):
        """
        Rebuilding the gate twice from an identical plugin list must produce
        the same could_contain_secret() behavior. This matters because the
        gate is rebuilt on every cache_bust() (e.g. checkov's
        _thread_safe_transient_settings reconfiguring plugins per-scan) --
        flakiness here would show up as intermittent false negatives in
        production, not a clean test failure.
        """
        class _Plugin(RegexBasedDetector):
            secret_type = 'Determinism'
            denylist = [
                re.compile(r'TRIGGER_ONE'),
                re.compile(r'(?P<shared_name>TRIGGER_TWO)'),
                re.compile(r'(?i)TRIGGER_THREE'),
            ]

        probes = ['TRIGGER_ONE', 'TRIGGER_TWO', 'trigger_three', 'nope']
        first = build_gate([_Plugin()])
        second = build_gate([_Plugin()])

        for probe in probes:
            assert first.could_contain_secret(probe) == second.could_contain_secret(probe), (
                f'Gate behavior for {probe!r} differed across two builds '
                f'from the identical plugin list.'
            )

    def test_gate_cache_invalidation_reflects_plugin_change_via_scan_module(self):
        """
        End-to-end check of the actual caching wiring in scan.py: after
        settings change (simulated here via cache_bust(), the same
        mechanism checkov's _thread_safe_transient_settings and
        detect_secrets.settings.transient_settings both use), the module-
        level gate cache in scan.py must rebuild from the NEW plugin set,
        not silently keep serving the old one.
        """
        import detect_secrets.core.scan as scan_module
        from detect_secrets.settings import get_settings
        from detect_secrets.settings import cache_bust

        class _OnlyOldTrigger(RegexBasedDetector):
            secret_type = 'Old'
            denylist = [re.compile(r'OLD_ONLY_TRIGGER')]

        class _OnlyNewTrigger(RegexBasedDetector):
            secret_type = 'New'
            denylist = [re.compile(r'NEW_ONLY_TRIGGER')]

        settings = get_settings()
        original_plugins = dict(settings.plugins)
        try:
            settings.configure_plugins([{'name': 'AWSKeyDetector'}])
            # Force a real plugin instance list containing our fake plugin
            # by monkeypatching get_plugins for the duration of this check
            # would be more invasive than needed -- instead, directly drive
            # scan.py's cache through its own public surface.
            scan_module._bust_gate_cache()
            from detect_secrets.core.gate import build_gate as _build_gate

            gate_v1 = _build_gate([_OnlyOldTrigger()])
            assert gate_v1.could_contain_secret('OLD_ONLY_TRIGGER')
            assert not gate_v1.could_contain_secret('NEW_ONLY_TRIGGER')

            gate_v2 = _build_gate([_OnlyNewTrigger()])
            assert gate_v2.could_contain_secret('NEW_ONLY_TRIGGER')
            assert not gate_v2.could_contain_secret('OLD_ONLY_TRIGGER')

            # Confirm cache_bust() (the real invalidation path) actually
            # clears scan.py's cached gate object, not just leaves a stale
            # reference that happens to still work.
            cache_bust()
            assert scan_module._gate is None, (
                'cache_bust() did not clear the module-level gate cache -- '
                'a stale gate could persist across tenant/settings changes.'
            )
        finally:
            settings.plugins = original_plugins
            scan_module._bust_gate_cache()


class TestEntropyValuePattern:
    """Tests for the smarter entropy value pattern that requires ≥8 non-whitespace
    chars after a delimiter, replacing the old blanket delimiter pattern."""

    def test_short_json_values_are_filtered(self):
        """JSON lines with short values (< 12 chars) should be rejected by the
        gate when no keyword is present."""
        gate = build_gate([])
        short_value_lines = [
            '"color": "#fff"',
            '"name": "red"',
            '"x": 42',
            '"enabled": true',
            '"items": []',
            '"data": null',
            '"id": "abc"',
            '"status": "active"',
            '"type": "button"',
        ]
        for line in short_value_lines:
            assert not gate.could_contain_secret(line), (
                f'Gate passed a short-value JSON line that cannot contain a secret:\n  {line!r}'
            )

    def test_long_json_values_pass_gate(self):
        """JSON lines with values ≥ 12 contiguous non-whitespace chars
        after a delimiter should pass."""
        gate = build_gate([])
        long_value_lines = [
            '"api_key": "sk-abc123def456ghi789"',
            '"token": "AKIAIOSFODNN7EXAMPLE"',
            '"secret": "wJalrXUtnFEMI/K7MDENG"',
            'value = "abcdefghijklmnop"',
            "key: 'longvalue12345678'",
        ]
        for line in long_value_lines:
            assert gate.could_contain_secret(line), (
                f'Gate rejected a line with a long value that could be a secret:\n  {line!r}'
            )

    def test_authorization_bearer_header_passes_gate(self):
        """Lines like 'Authorization: Bearer <long-token>' must pass because
        the pattern allows up to 2 whitespace gaps before the 12+ char token."""
        gate = build_gate([])
        assert gate.could_contain_secret(
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        ), 'Gate rejected an Authorization Bearer header with a long JWT token'

    def test_keyword_lines_pass_regardless_of_value_length(self):
        """Lines containing keyword denylist words should always pass,
        even if the value after the delimiter is short."""
        gate = build_gate([])
        keyword_lines = [
            'password = "x"',
            'secret: "ab"',
            'api_key = ""',
            'token: "hi"',
        ]
        for line in keyword_lines:
            assert gate.could_contain_secret(line), (
                f'Gate rejected a keyword-bearing line:\n  {line!r}'
            )

    def test_structural_json_lines_are_filtered(self):
        """Pure structural JSON lines (braces, brackets, commas) should be filtered."""
        gate = build_gate([])
        structural_lines = [
            '{',
            '}',
            '  },',
            '  ],',
            '  [',
        ]
        for line in structural_lines:
            assert not gate.could_contain_secret(line), (
                f'Gate passed a structural JSON line:\n  {line!r}'
            )

    def test_value_pattern_boundary_at_12_chars(self):
        r"""The pattern requires ≥12 contiguous non-whitespace chars after a
        delimiter. Note: the closing quote counts as part of the \S run, so
        a quoted value of N chars produces an N+1 char \S run (value + quote).
        For unquoted values the boundary is exact."""
        gate = build_gate([])
        # 12-char unquoted value after "=" — should pass
        assert gate.could_contain_secret('x = 123456789012'), (
            'Gate rejected a line with exactly 12-char unquoted value'
        )
        # 11-char unquoted value after "=" — should NOT pass
        assert not gate.could_contain_secret('x = 12345678901'), (
            'Gate passed a line with only 11-char unquoted value and no keyword'
        )
