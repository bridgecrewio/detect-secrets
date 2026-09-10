"""
Tests for the DI plan cache optimization in inject.py.

The cache eliminates repeated inspect calls in the hot path by caching
the parameter plan for each callable after the first call.

The isinstance(func, MethodType) optimization replaces the slower
inspect.ismethod(func) call — both are semantically identical but
isinstance avoids the function-call overhead of the inspect module.
"""
from __future__ import annotations

import types
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


# --- isinstance optimization tests -------------------------------------------

class _PluginWithReturn:
    """Plugin that returns identifiable values so we can assert on real results."""
    def analyze_line(self, filename: str, line: str, line_number: int = 0) -> list:
        return [f'found:{line}']

    def filter_check(self, line: str) -> bool:
        return 'secret' in line


def _plain_function(filename: str, line: str) -> str:
    return f'plain:{filename}:{line}'


def test_isinstance_bound_method_returns_correct_result():
    """Bound method dispatch via isinstance(func, MethodType) returns the
    real result from the plugin method."""
    plugin = _PluginWithReturn()
    inject_module._plan_cache.clear()

    result = call_function_with_arguments(
        plugin.analyze_line,
        filename='test.py',
        line='hello',
        line_number=1,
    )
    assert result == ['found:hello']


def test_isinstance_plain_function_returns_correct_result():
    """Plain (non-bound) function dispatch returns the real result."""
    inject_module._plan_cache.clear()

    result = call_function_with_arguments(
        _plain_function,
        filename='test.py',
        line='world',
    )
    assert result == 'plain:test.py:world'


def test_isinstance_bound_method_ignores_extra_kwargs():
    """Extra kwargs not in the method signature are silently ignored."""
    plugin = _PluginWithReturn()
    inject_module._plan_cache.clear()

    result = call_function_with_arguments(
        plugin.analyze_line,
        filename='test.py',
        line='data',
        line_number=5,
        extra_kwarg='should_be_ignored',
        another_extra=42,
    )
    assert result == ['found:data']


def test_isinstance_no_inspect_module_imported():
    """The inject module should no longer import the inspect module at all."""
    import importlib
    import detect_secrets.util.inject as fresh_module
    # Check that 'inspect' is not in the module's namespace
    assert not hasattr(fresh_module, 'inspect'), (
        'inject.py still imports the inspect module — '
        'isinstance(func, MethodType) should have replaced all inspect.ismethod() calls'
    )


def test_isinstance_method_type_detection_matches_inspect():
    """isinstance(func, MethodType) must agree with the old inspect.ismethod()
    for both bound methods and plain functions."""
    import inspect
    plugin = _PluginWithReturn()

    bound = plugin.analyze_line
    assert isinstance(bound, types.MethodType) == inspect.ismethod(bound), (
        'isinstance(func, MethodType) disagrees with inspect.ismethod() for a bound method'
    )

    assert isinstance(_plain_function, types.MethodType) == inspect.ismethod(_plain_function), (
        'isinstance(func, MethodType) disagrees with inspect.ismethod() for a plain function'
    )


def test_isinstance_cached_and_uncached_paths_produce_same_result():
    """Both the cached (DI_CACHE_ENABLED=True) and uncached paths must
    produce identical results for the same input."""
    plugin = _PluginWithReturn()
    inject_module._plan_cache.clear()

    # Cached path
    result_cached = call_function_with_arguments(
        plugin.analyze_line,
        filename='f.py',
        line='test_line',
        line_number=1,
    )

    # Uncached path
    with patch.object(inject_module, '_DI_CACHE_ENABLED', False):
        result_uncached = call_function_with_arguments(
            plugin.analyze_line,
            filename='f.py',
            line='test_line',
            line_number=1,
        )

    assert result_cached == result_uncached == ['found:test_line']
