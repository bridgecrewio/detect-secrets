"""
Unit tests for the filter list cache in scan.py.

TDD: write failing tests first, then implement.
"""
from __future__ import annotations


def test_filter_cache_exists():
    """_filter_cache must be importable from scan module."""
    from detect_secrets.core.scan import _filter_cache
    assert isinstance(_filter_cache, dict)


def test_get_filters_with_parameter_populates_cache():
    """First call should populate the cache."""
    from detect_secrets.core import scan
    from detect_secrets.settings import default_settings

    scan._filter_cache.clear()

    with default_settings():
        scan.get_filters_with_parameter('line')
        assert frozenset({'line'}) in scan._filter_cache, (
            'Cache should contain entry for ("line",) after first call'
        )


def test_get_filters_with_parameter_reuses_cache():
    """Second call with same parameters should return cached result."""
    from detect_secrets.core import scan
    from detect_secrets.settings import default_settings

    scan._filter_cache.clear()

    with default_settings():
        result1 = scan.get_filters_with_parameter('line')
        result2 = scan.get_filters_with_parameter('line')
        assert result1 is result2, (
            'Second call should return the exact same list object (cache hit)'
        )


def test_filter_cache_cleared_on_cache_bust():
    """cache_bust() must clear _filter_cache."""
    from detect_secrets.core import scan
    from detect_secrets.settings import default_settings, cache_bust

    with default_settings():
        scan.get_filters_with_parameter('line')
        assert len(scan._filter_cache) > 0

        cache_bust()
        assert len(scan._filter_cache) == 0, (
            '_filter_cache must be empty after cache_bust()'
        )


def test_filter_cache_disabled_by_env_var():
    """When DETECT_SECRETS_PERF_FILTER_CACHE=0, cache must not be populated."""
    # Instead of importlib.reload() (which doesn't update already-imported references),
    # use mock.patch.object to patch the module-level boolean directly:
    from unittest.mock import patch
    from detect_secrets.core import scan as scan_module
    from detect_secrets.settings import default_settings

    scan_module._filter_cache.clear()

    with patch.object(scan_module, '_FILTER_CACHE_ENABLED', False):
        with default_settings():
            scan_module.get_filters_with_parameter('line')
            assert len(scan_module._filter_cache) == 0, (
                'Cache should not be populated when _FILTER_CACHE_ENABLED=False'
            )
