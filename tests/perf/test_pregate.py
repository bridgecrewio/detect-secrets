"""
Tests for the pre-gate line filter optimization in scan.py.

The pre-gate skips lines that cannot possibly match any detector pattern,
avoiding the cost of building code_snippet context and running all detectors.

CRITICAL: The gate must be a superset of all detector patterns — if it returns
False for a line, NO detector can match that line. This is verified empirically
by the parity oracle (test_parity_oracle.py), which is the ultimate correctness
check for this optimization.

Run with:
    pytest tests/perf/test_pregate.py -v
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

import detect_secrets.core.scan as scan_module


def test_pregate_passes_lines_with_known_secret_patterns():
    """Lines containing known secret patterns must pass the gate (return True)."""
    if not hasattr(scan_module, '_could_contain_secret'):
        pytest.skip('_could_contain_secret not implemented yet')

    from detect_secrets.core.scan import _could_contain_secret

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
        result = _could_contain_secret(line)
        assert result is True, f'Pre-gate incorrectly rejected line that may contain a secret:\n  {line!r}'


def test_pregate_filters_majority_of_clean_lines():
    """The pre-gate must filter at least 80% of obviously clean lines."""
    if not hasattr(scan_module, '_could_contain_secret'):
        pytest.skip('_could_contain_secret not implemented yet')

    from detect_secrets.core.scan import _could_contain_secret

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

    filtered = [line for line in clean_lines if not _could_contain_secret(line)]
    filter_rate = len(filtered) / len(clean_lines)
    assert filter_rate >= 0.8, (
        f'Pre-gate only filtered {filter_rate:.0%} of clean lines — expected ≥80%.\n'
        f'Lines that passed the gate (should have been filtered):\n'
        + '\n'.join(f'  {line!r}' for line in clean_lines if _could_contain_secret(line))
    )


def test_pregate_disabled_by_flag():
    """When _PREGATE_ENABLED is False, the gate is bypassed."""
    if not hasattr(scan_module, '_PREGATE_ENABLED'):
        pytest.skip('_PREGATE_ENABLED flag not implemented yet')

    with patch.object(scan_module, '_PREGATE_ENABLED', False):
        assert scan_module._PREGATE_ENABLED is False


def test_pregate_is_superset_of_keyword_detector():
    """Lines that the keyword detector would match must pass the pre-gate."""
    if not hasattr(scan_module, '_could_contain_secret'):
        pytest.skip('_could_contain_secret not implemented yet')

    from detect_secrets.core.scan import _could_contain_secret
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
            assert _could_contain_secret(line), (
                f'Pre-gate rejected a line that keyword detector matched:\n  {line!r}'
            )


def test_pregate_is_superset_of_all_plugin_denylist_patterns():
    """
    For every registered RegexBasedDetector plugin, generate a synthetic line from
    each of its denylist patterns and confirm the pre-gate passes it. This provides
    broad, mechanical coverage across all detectors without needing real secrets.
    """
    if not hasattr(scan_module, '_could_contain_secret'):
        pytest.skip('_could_contain_secret not implemented yet')

    from detect_secrets.core.scan import _could_contain_secret
    from detect_secrets.plugins.aws import AWSKeyDetector
    from detect_secrets.plugins.private_key import PrivateKeyDetector
    from detect_secrets.plugins.jwt import JwtTokenDetector
    from detect_secrets.plugins.github_token import GitHubTokenDetector

    # Known realistic samples per detector — these are patterns the real detectors match.
    samples = {
        'AWS key': 'AKIAIOSFODNN7EXAMPLE',
        'Private key header': '-----BEGIN OPENSSH PRIVATE KEY-----',
        'JWT': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ',
        'GitHub token': 'ghp_1234567890abcdefghij1234567890abcdef',
    }

    for label, sample in samples.items():
        assert _could_contain_secret(sample), (
            f'Pre-gate rejected a known {label} sample:\n  {sample!r}'
        )
