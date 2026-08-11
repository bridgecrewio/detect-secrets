"""
Tests for the DI plan cache optimization in inject.py.

The cache eliminates repeated inspect calls in the hot path by caching
the parameter plan for each callable after the first call.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

import detect_secrets.util.inject as inject_module
from detect_secrets.util.inject import call_function_with_arguments


class _FakePlugin:
    def analyze_line(self, filename: str, line: str, line_number: int = 0) -> list:
        return []

    def other_method(self, line: str) -> list:
        return []


def test_di_cache_reduces_make_function_self_aware_calls():
    """
    After the first call, make_function_self_aware should NOT be called again
    for the same bound method (same underlying function).
    """
    plugin = _FakePlugin()

    with patch.object(inject_module, 'make_function_self_aware', wraps=inject_module.make_function_self_aware) as mock_msfa:
        # Call 1: should call make_function_self_aware
        call_function_with_arguments(
            plugin.analyze_line,
            filename='test.py',
            line='hello world',
            line_number=1,
        )
        # Call 2: same method, should NOT call make_function_self_aware again
        call_function_with_arguments(
            plugin.analyze_line,
            filename='test.py',
            line='another line',
            line_number=2,
        )
        # Call 3: same method again
        call_function_with_arguments(
            plugin.analyze_line,
            filename='test.py',
            line='third line',
            line_number=3,
        )

    # With caching: make_function_self_aware called only once (or zero times if we bypass it entirely)
    # Without caching: called 3 times
    assert mock_msfa.call_count <= 1, (
        f'make_function_self_aware called {mock_msfa.call_count} times — '
        f'expected ≤1 (cache should prevent repeated calls)'
    )


def test_di_cache_separate_entries_for_different_methods():
    """Different methods get separate cache entries."""
    plugin = _FakePlugin()

    with patch.object(inject_module, 'make_function_self_aware', wraps=inject_module.make_function_self_aware) as mock_msfa:
        call_function_with_arguments(plugin.analyze_line, filename='f.py', line='x', line_number=1)
        call_function_with_arguments(plugin.other_method, line='x')
        # Second calls — should use cache
        call_function_with_arguments(plugin.analyze_line, filename='f.py', line='y', line_number=2)
        call_function_with_arguments(plugin.other_method, line='y')

    # Each distinct method called once for make_function_self_aware (or zero if bypassed)
    assert mock_msfa.call_count <= 2, (
        f'Expected ≤2 make_function_self_aware calls (one per distinct method), got {mock_msfa.call_count}'
    )


def test_di_cache_correct_results():
    """Cached calls return the same results as uncached calls."""
    plugin = _FakePlugin()

    result1 = call_function_with_arguments(
        plugin.analyze_line,
        filename='test.py',
        line='hello',
        line_number=1,
    )
    result2 = call_function_with_arguments(
        plugin.analyze_line,
        filename='test.py',
        line='hello',
        line_number=1,
    )
    assert result1 == result2 == []


def test_di_cache_self_not_in_injectable():
    """'self' must NOT be in the cached injectable variables for bound methods."""
    plugin = _FakePlugin()

    # Clear cache to force a fresh computation
    if hasattr(inject_module, '_plan_cache'):
        inject_module._plan_cache.clear()

    call_function_with_arguments(
        plugin.analyze_line,
        filename='test.py',
        line='hello',
        line_number=1,
    )

    if hasattr(inject_module, '_plan_cache'):
        cache_key = id(plugin.analyze_line.__func__)
        if cache_key in inject_module._plan_cache:
            plan = inject_module._plan_cache[cache_key]
            injectable = plan[0]  # first element is the injectable set
            assert 'self' not in injectable, (
                f"'self' found in injectable variables: {injectable}. "
                'Bound methods carry self implicitly — it must not be injected.'
            )


def test_di_cache_disabled_by_flag():
    """When _DI_CACHE_ENABLED is False, the slow path runs (make_function_self_aware called each time)."""
    plugin = _FakePlugin()

    if not hasattr(inject_module, '_DI_CACHE_ENABLED'):
        pytest.skip('_DI_CACHE_ENABLED flag not implemented yet')

    with patch.object(inject_module, '_DI_CACHE_ENABLED', False):
        with patch.object(inject_module, 'make_function_self_aware', wraps=inject_module.make_function_self_aware) as mock_msfa:
            call_function_with_arguments(plugin.analyze_line, filename='f.py', line='x', line_number=1)
            call_function_with_arguments(plugin.analyze_line, filename='f.py', line='y', line_number=2)

        assert mock_msfa.call_count >= 2, (
            f'Expected ≥2 calls when cache disabled, got {mock_msfa.call_count}'
        )
