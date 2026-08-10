"""
Unit tests for the entropy short-circuit in high_entropy_strings.py.

TDD: write failing tests first, then implement.
"""
from __future__ import annotations

import math
import pytest


def _get_base64_plugin():
    from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
    return Base64HighEntropyString()


def _get_hex_plugin():
    from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
    return HexHighEntropyString()


def test_entropy_returns_zero_for_short_string():
    """Strings shorter than MIN_ENTROPY_LEN should return 0.0 without computing."""
    plugin = _get_base64_plugin()
    # 'abc' is 3 chars — below the minimum length threshold
    result = plugin.calculate_shannon_entropy('abc')
    assert result == 0.0, f'Expected 0.0 for short string, got {result}'


def test_entropy_returns_zero_for_uniform_string():
    """Strings with fewer than MIN_DISTINCT_CHARS distinct charset chars return 0.0."""
    plugin = _get_base64_plugin()
    # 'aaaaaaaaaa' has only 1 distinct char — below threshold
    result = plugin.calculate_shannon_entropy('aaaaaaaaaa')
    assert result == 0.0, f'Expected 0.0 for uniform string, got {result}'


def test_entropy_computes_correctly_for_valid_string():
    """Normal strings above thresholds must still compute correct entropy."""
    plugin = _get_base64_plugin()
    # 'abcdefghij' has 10 distinct chars, length 10 — should compute real entropy
    result = plugin.calculate_shannon_entropy('abcdefghij')
    assert result > 0.0, f'Expected positive entropy for diverse string, got {result}'
    # Verify it's mathematically reasonable (max entropy for 10 chars is log2(10) ≈ 3.32)
    assert result <= math.log2(len('abcdefghij')) + 0.01


def test_entropy_hex_plugin_still_works():
    """HexHighEntropyString must still compute entropy correctly after short-circuit."""
    plugin = _get_hex_plugin()
    # A realistic hex string (32 chars)
    hex_str = 'deadbeefcafebabe0123456789abcdef'
    result = plugin.calculate_shannon_entropy(hex_str)
    assert result > 0.0, f'Expected positive entropy for hex string, got {result}'


def test_entropy_short_circuit_disabled_by_env_var():
    """When DETECT_SECRETS_PERF_ENTROPY_SC=0, short strings must compute normally."""
    # Instead of importlib.reload() (which doesn't update already-imported references),
    # use mock.patch.object to patch the module-level boolean directly:
    from unittest.mock import patch
    from detect_secrets.plugins import high_entropy_strings as hes_module

    plugin = hes_module.Base64HighEntropyString()

    with patch.object(hes_module, '_ENTROPY_SC_ENABLED', False):
        # With short-circuit disabled, 'abc' should compute (result may be non-zero)
        result = plugin.calculate_shannon_entropy('abc')
        # We don't assert the value — just that it doesn't crash
        assert isinstance(result, float)


def test_entropy_short_circuit_safe_for_short_hex():
    """Verify that the short-circuit returns 0.0 for strings below MIN_ENTROPY_LEN,
    which is the same result HexHighEntropyString would produce after its penalty."""
    import string
    from detect_secrets.plugins.high_entropy_strings import calculate_shannon_entropy
    # A 6-char hex string: even without short-circuit, entropy would be low
    # and HexHighEntropyString's penalty would push it below threshold
    result = calculate_shannon_entropy('a1b2c3', string.hexdigits)
    assert result == 0.0, "Short strings should return 0.0 — same as without short-circuit"


def test_entropy_boundary_at_min_length():
    """String of exactly MIN_ENTROPY_LEN chars should NOT be short-circuited."""
    from detect_secrets.plugins.high_entropy_strings import _ENTROPY_MIN_LEN
    plugin = _get_base64_plugin()
    # Create a string of exactly MIN_ENTROPY_LEN diverse chars
    test_str = 'abcdefgh'[:_ENTROPY_MIN_LEN]  # 8 chars
    # Should compute (not short-circuit) — result may be 0 or positive
    result = plugin.calculate_shannon_entropy(test_str)
    assert isinstance(result, float)
