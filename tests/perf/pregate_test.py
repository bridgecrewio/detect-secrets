"""
Tests for the sound line pre-gate (v2) in scan.py / core/gate.py.

The pre-gate skips lines that cannot possibly match any *currently loaded*
plugin, avoiding the cost of building code_snippet context and running all
detectors on lines that are provably clean.

v1 of this gate (see git history) was one hand-written regex, built by
approximating each detector's trigger condition from memory. That approach
silently dropped real findings: a length threshold that didn't match a real
detector's shortest valid token, an entropy trigger keyed on length instead
of the real (length-less) delimiter precondition, and -- critically -- no
way to ever learn about tenant-defined custom/multiline policies, since the
gate was built once at import time.

v2 fixes this by building the gate from the plugins actually loaded for the
current scan (detect_secrets.core.gate.build_gate), using each plugin's own
`denylist` and the real `KeywordDetector.DENYLIST` rather than retyping
anything. Because it reads the live plugin set, it automatically widens
itself for tenant-specific custom regexes (checkov's CustomRegexDetector
stores them in the same `.denylist` attribute as every built-in plugin).

IMPORTANT: every real call site in scan.py (`scan_file`, `scan_diff`, etc.)
already guards with `if not get_plugins(): return` before the gate is ever
consulted -- so in real usage the gate is never built against an empty
plugin list. Tests here therefore use `default_settings()` (which loads
every built-in plugin) to match real usage, not the bare/no-settings state.

Run with:
    pytest tests/perf/pregate_test.py -v
"""
from __future__ import annotations

from unittest.mock import patch

import detect_secrets.core.scan as scan_module
from detect_secrets.settings import default_settings


def _fresh_gate():
    """Force the module-level gate cache to rebuild against whatever
    plugins are configured right now (mirrors what cache_bust() does when
    settings change mid-scan, e.g. a new tenant's custom policies load)."""
    scan_module._bust_gate_cache()
    return scan_module._could_contain_secret


def test_pregate_passes_lines_with_known_secret_patterns():
    """Lines containing known secret patterns must pass the gate (return True)."""
    with default_settings():
        could_contain_secret = _fresh_gate()

        must_pass = [
            'password = "supersecret123"',
            'api_key = "AKIAIOSFODNN7EXAMPLE"',
            'token: ghp_1234567890abcdefghij1234567890abcdef',
            '-----BEGIN RSA PRIVATE KEY-----',
            'secret_key = "abc123def456ghi789jkl012mno345pqr678"',
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'private_key = "-----BEGIN PRIVATE KEY-----"',
            'db_password = "MyS3cr3tP@ssw0rd"',
            'GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456',
        ]

        for line in must_pass:
            assert could_contain_secret(line), (
                f'Pre-gate incorrectly rejected line that may contain a secret:\n  {line!r}'
            )


def test_pregate_filters_majority_of_clean_lines():
    """The pre-gate must filter at least 80% of obviously clean lines."""
    with default_settings():
        could_contain_secret = _fresh_gate()

        clean_lines = [
            'import java.util.concurrent.ConcurrentHashMap;',
            'public class MyClass {',
            '    return result;',
            '    int x = 5;',
            '    System.out.println(message);',
            '// This is a comment',
            '    }',
            'package com.example.service;',
            '    private final List<String> items;',
            '    super(parent);',
        ]

        filtered = [line for line in clean_lines if not could_contain_secret(line)]
        filter_rate = len(filtered) / len(clean_lines)
        assert filter_rate >= 0.8, (
            f'Pre-gate only filtered {filter_rate:.0%} of clean lines — expected ≥80%.\n'
            f'Lines that passed the gate (should have been filtered):\n'
            + '\n'.join(f'  {line!r}' for line in clean_lines if could_contain_secret(line))
        )


def test_pregate_disabled_by_flag():
    """When _PREGATE_ENABLED is False, callers bypass the gate."""
    with patch.object(scan_module, '_PREGATE_ENABLED', False):
        assert scan_module._PREGATE_ENABLED is False


def test_pregate_is_superset_of_keyword_detector():
    """Lines that the keyword detector would match must pass the pre-gate."""
    with default_settings():
        could_contain_secret = _fresh_gate()

        from detect_secrets.plugins.keyword import KeywordDetector

        detector = KeywordDetector()
        keyword_lines = [
            'password = "test123"',
            'secret = "abc"',
            'api_key = "xyz"',
            'token = "123"',
            'passwd = "abc"',
        ]

        for line in keyword_lines:
            findings = list(detector.analyze_string(line))
            if findings:
                assert could_contain_secret(line), (
                    f'Pre-gate rejected a line that keyword detector matched:\n  {line!r}'
                )


def test_pregate_is_superset_of_all_plugin_denylist_patterns():
    """
    For every registered RegexBasedDetector plugin, generate a synthetic line from
    each of its denylist patterns and confirm the pre-gate passes it. This provides
    broad, mechanical coverage across all detectors without needing real secrets.
    """
    with default_settings():
        could_contain_secret = _fresh_gate()

        # Known realistic samples per detector — these are patterns the real detectors match.
        samples = {
            'AWS key': 'AKIAIOSFODNN7EXAMPLE',
            'Private key header': '-----BEGIN OPENSSH PRIVATE KEY-----',
            'JWT': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ',
            'GitHub token': 'ghp_1234567890abcdefghij1234567890abcdef',
        }

        for label, sample in samples.items():
            assert could_contain_secret(sample), (
                f'Pre-gate rejected a known {label} sample:\n  {sample!r}'
            )


# --- v2-specific regression coverage -------------------------------------
# These are exactly the categories that broke the v1 (hand-written) gate.
# Each one failing here means the gate has regressed to v1-style unsoundness.

def test_pregate_catches_short_artifactory_style_token():
    """
    v1 regression: the hand-written gate required a 15+ char high-entropy
    run, but a real Artifactory AKC token can be 13 chars. The real
    ArtifactoryDetector.denylist pattern requires 10+ chars after `AKC` --
    imported directly here, not retyped, so this can't drift again.
    """
    with default_settings():
        could_contain_secret = _fresh_gate()
        assert could_contain_secret('value = AKCghijklmnop'), (
            'Pre-gate rejected a short (13-char) Artifactory-style token — '
            'this is the exact class of miss that broke the v1 gate.'
        )


def test_pregate_catches_url_password_with_at_sign_in_userinfo():
    """
    v1 regression: the hand-written URL-credentials pattern
    (`://[^@\\s]+:[^@\\s]+@`) forbade '@' anywhere in the userinfo, which is
    narrower than the real BasicAuthDetector regex. Using the real,
    imported pattern instead of an approximation fixes this by construction.
    """
    with default_settings():
        could_contain_secret = _fresh_gate()
        line = 'endpoint = https://svcuser:p@ssw0rd-value@internal.example.com/api/v2/resource'
        assert could_contain_secret(line), (
            'Pre-gate rejected a URL-embedded password containing "@" in the '
            'userinfo — the real BasicAuthDetector pattern allows this.'
        )


def test_pregate_catches_keyword_free_entropy_candidate():
    """
    v1 regression: entropy candidates were gated by a length guess, not the
    real (length-less) delimiter precondition of HighEntropyStringsPlugin's
    extraction regex. A benign key name with a high-entropy value and no
    "secret-sounding" keyword anywhere on the line must still survive.
    """
    with default_settings():
        could_contain_secret = _fresh_gate()
        line = '  identifier: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"'
        assert could_contain_secret(line), (
            'Pre-gate rejected a keyword-free high-entropy candidate line — '
            'the real extraction regex only requires a delimiter, not a keyword.'
        )


def test_pregate_widens_automatically_for_custom_prerun_policy():
    """
    v1 regression (the core one): checkov's CustomRegexDetector stores a
    tenant's `prerun` trigger keyword (e.g. a multiline policy keyed on the
    word "Algolia") in its own `.denylist`, exactly like a built-in plugin.
    Because the gate is rebuilt from the live plugin list, loading a plugin
    whose denylist contains an arbitrary custom trigger word must make that
    word survive the gate -- with no special-casing required in scan.py or
    core/gate.py.
    """
    from detect_secrets.core.gate import build_gate
    from detect_secrets.plugins.base import RegexBasedDetector
    import re

    class _FakeCustomTenantPlugin(RegexBasedDetector):
        """Stands in for checkov's CustomRegexDetector with one tenant
        policy loaded, without requiring checkov as a test dependency."""
        secret_type = 'Fake Tenant Custom Policy'
        denylist = [re.compile(r'(?i)(?:algolia)')]

    gate = build_gate([_FakeCustomTenantPlugin()])
    assert gate.could_contain_secret('Algolia'), (
        'Gate did not widen for a custom-plugin denylist trigger word — '
        'tenant-specific multiline/custom policies would silently lose '
        'pre-gate coverage.'
    )
    assert not gate.untriggerable_plugins, (
        f'Custom plugin fell back to the untriggerable/standalone path '
        f'unexpectedly: {gate.untriggerable_plugins}'
    )


def test_pregate_handles_leading_inline_flags_in_custom_patterns():
    """
    Regression for the specific bug found while building v2: Python's `re`
    only allows a *global* inline flag group (e.g. `(?i)`) as the very first
    token of a pattern. checkov wraps every custom regex in `(?i)(?:...)`
    (see checkov/secrets/plugins/load_detectors.py), so combining such a
    pattern into the gate's alternation via naive string concatenation
    raises `re.error: global flags not at the start of the expression`.
    The gate must convert this into the scoped form (`(?i:...)`), which is
    legal anywhere, instead of silently falling back or crashing.
    """
    from detect_secrets.core.gate import build_gate
    from detect_secrets.plugins.base import RegexBasedDetector
    import re

    class _FakeCaseInsensitiveCustomPlugin(RegexBasedDetector):
        secret_type = 'Fake Case Insensitive Custom Policy'
        denylist = [re.compile('(?i)(?:mysecretword)')]

    gate = build_gate([_FakeCaseInsensitiveCustomPlugin()])
    assert gate.could_contain_secret('MYSECRETWORD'), (
        'Gate rejected an uppercase match for a case-insensitive custom '
        'pattern — leading (?i) flag handling regressed.'
    )
    assert not gate.untriggerable_plugins, (
        'Custom plugin with a leading (?i) flag unexpectedly fell back to '
        'the untriggerable/standalone path.'
    )


def test_pregate_survives_whole_file_multiline_private_key_pattern():
    """
    Regression found while building v2: PrivateKeyDetector's real denylist
    pattern is ONE regex spanning header + base64 body + footer -- by
    construction, no single line can ever fully match it. The plugin's real
    trigger condition is much weaker ("any line reaches analyze_line() at
    all" -- it then re-reads and re-scans the whole file itself, see
    PrivateKeyDetector.analyze_line). A naive "does this line fully match
    the plugin's denylist pattern" gate check would therefore reject EVERY
    line of a real private-key file -- worse than v1, which happened to get
    this right only because it hardcoded "-----BEGIN" as a literal keyword.

    This must pass for the plugin's OWN real, imported pattern (not a
    hand-copied approximation), on each line of a realistic multi-line PEM
    block, including a body line with no keyword anywhere on it.
    """
    from detect_secrets.plugins.private_key import PrivateKeyDetector

    with default_settings():
        could_contain_secret = _fresh_gate()

        pem_lines = [
            '-----BEGIN RSA PRIVATE KEY-----',
            'MIIBOwIBAAJBAK7SamplekeyMaterialForTestingOnlyNotARealKeyAtAll1234',
            'QJBAKexampleBodyLineWithNoKeywordAnywhereOnIt',
            '-----END RSA PRIVATE KEY-----',
        ]

        # The real plugin only needs ANY line to survive to trigger its
        # whole-file re-scan -- confirm at least the header line does.
        assert any(could_contain_secret(line) for line in pem_lines), (
            'No line of a realistic PEM block survived the gate — '
            'PrivateKeyDetector would never be invoked for this file.\n'
            + '\n'.join(f'  {line!r}' for line in pem_lines)
        )
        # The header line specifically must survive, since it's the one
        # every real PEM file is guaranteed to contain, regardless of body
        # content, key type, or line wrapping.
        assert could_contain_secret('-----BEGIN RSA PRIVATE KEY-----'), (
            'Pre-gate rejected a PEM header line — PrivateKeyDetector '
            'would never run for any file whose only "keyword-shaped" '
            'line is the header.'
        )

    # Sanity: also verify against the real, unmodified, imported
    # PrivateKeyDetector.denylist pattern to make sure the assertion above
    # isn't accidentally passing due to a coincidental keyword elsewhere in
    # KeywordDetector's denylist (e.g. "private" also matches "PRIVATE KEY").
    real_pattern = PrivateKeyDetector.denylist[0]
    assert 'PRIVATE KEY' in real_pattern.pattern


def test_pregate_widens_for_multiline_policy_without_prerun():
    """
    checkov's CustomRegexDetector has a SECOND multiline mechanism, stored
    in `.multiline_deny_list` (a different attribute than `.denylist`) --
    used for `isMultiline: true` policies that don't define a `prerun`
    keyword. A gate that only reads `.denylist` would silently miss these
    entirely. The gate must read both attributes generically (duck-typed,
    no checkov import required in core/gate.py).
    """
    from detect_secrets.core.gate import build_gate
    from detect_secrets.plugins.base import RegexBasedDetector
    import re

    class _FakeMultilineNoPrerunPlugin(RegexBasedDetector):
        """Stands in for CustomRegexDetector with an isMultiline-without-
        prerun policy loaded -- has NO real denylist, only
        multiline_deny_list, mirroring the real attribute split."""
        secret_type = 'Fake Multiline No-Prerun Policy'
        denylist: list = []
        multiline_deny_list = [re.compile(r'Algolia\n((?:.*\n)+?)ZZDONEZZ')]

    gate = build_gate([_FakeMultilineNoPrerunPlugin()])
    assert gate.could_contain_secret('Algolia'), (
        'Gate did not widen for a multiline_deny_list trigger keyword — '
        'checkov isMultiline-without-prerun policies would silently lose '
        'pre-gate coverage.'
    )
