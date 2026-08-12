import inspect
import os
from types import MethodType
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import Set
from typing import Tuple
from typing import Union

from ..custom_types import SelfAwareCallable


# NOTE: id() returns the memory address in CPython, which can be reused after GC.
# This is safe here because plugin instances are long-lived (created once per scan
# and held in the settings registry). id() reuse is not a concern in practice.
_plan_cache: Dict[int, Tuple[Set[str], bool]] = {}

# Feature flag: set DETECT_SECRETS_PERF_DI_CACHE=0 to disable and use the original slow path.
# Default: enabled (True).
_DI_CACHE_ENABLED: bool = os.getenv('DETECT_SECRETS_PERF_DI_CACHE', '1') != '0'


def call_function_with_arguments(
    func: Union[Callable, SelfAwareCallable],
    **kwargs: Any,
) -> Any:
    """
    Calls func with only the keyword arguments it actually accepts.

    Uses a plan cache to avoid repeated inspect calls in the hot path.
    The cache is keyed by id(func.__func__) for bound methods (stable across
    calls) or id(func) for plain functions.

    NOTE: Interaction between cached and uncached paths:
    When _DI_CACHE_ENABLED=False, the original make_function_self_aware() path runs.
    That path mutates the class-level function object by setting injectable_variables.
    When the cache is re-enabled, the cache is empty and will be rebuilt correctly.
    The two paths are independent.

    :raises: TypeError
    """
    if _DI_CACHE_ENABLED:
        return _call_with_cache(func, **kwargs)
    else:
        return _call_without_cache(func, **kwargs)


def _call_with_cache(func: Union[Callable, SelfAwareCallable], **kwargs: Any) -> Any:
    """Fast path: use cached plan to avoid repeated inspect calls."""
    is_bound = inspect.ismethod(func)

    # Use the underlying function's id for bound methods — stable across calls
    # (Python creates a new bound method object on each attribute access, but
    # func.__func__ is the stable underlying function object)
    cache_key = id(cast(MethodType, func).__func__) if is_bound else id(func)

    plan = _plan_cache.get(cache_key)
    if plan is None:
        plan = _build_plan(func, is_bound)
        _plan_cache[cache_key] = plan

    injectable, _ = plan

    # For bound methods, self is carried by the method itself — no need to inject it
    filtered = {k: kwargs[k] for k in injectable if k in kwargs}
    return func(**filtered)


def _build_plan(func: Union[Callable, SelfAwareCallable], is_bound: bool) -> Tuple[Set[str], bool]:
    """
    Build the injection plan for a callable.
    Returns (injectable_vars, is_bound).

    For bound methods, we use func.__func__ to get stable parameter names,
    then drop index 0 ('self') because bound methods already carry the instance.
    """
    if is_bound:
        # Use the underlying unbound function to get all parameter names
        all_vars = get_injectable_variables(cast(MethodType, func).__func__)
        # Drop 'self' (index 0) — bound methods carry self implicitly
        injectable = set(all_vars[1:])
    else:
        injectable = set(get_injectable_variables(func))

    return injectable, is_bound


def _call_without_cache(func: Union[Callable, SelfAwareCallable], **kwargs: Any) -> Any:
    """Slow path (original implementation): used when _DI_CACHE_ENABLED=False."""
    # First, we ensure that the function we're going to inject values into is self-aware.
    function = func if isinstance(func, SelfAwareCallable) else make_function_self_aware(func)

    # If `function` is derived from a method, we add the instance of the class by default.
    if inspect.ismethod(func) and not inspect.ismethod(function):
        kwargs[get_injectable_variables(func)[0]] = func.__self__

    variables_to_inject = set(kwargs.keys())
    values = {
        key: kwargs[key]
        for key in (variables_to_inject & function.injectable_variables)
    }

    return function(**values)


def make_function_self_aware(func: Callable) -> SelfAwareCallable:
    """
    A SelfAwareCallable is one that is aware of its own injectable variables, through the
    `func.injectable_variables` attribute.
    """
    if hasattr(func, 'injectable_variables'):
        return cast(SelfAwareCallable, func)

    # We can't add arbitrary attributes to methods, but we can to functions. Therefore,
    # we need to reference the underlying function itself.
    if inspect.ismethod(func):
        klass = func.__self__.__class__
        function = getattr(klass, func.__name__)
        function.injectable_variables = set(get_injectable_variables(func))

        function.path = f'{klass}.{func.__name__}'
    else:
        function = func
        function.path = func.__name__

    return cast(SelfAwareCallable, function)


def get_injectable_variables(func: Callable) -> Tuple[str, ...]:
    """
    The easiest way to understand this is to see it as an example:
        >>> def func(a, b=1, *args, c, d=2, **kwargs):
        ...     e = 5
        >>>
        >>> print(func.__code__.co_varnames)
        ('a', 'b', 'c', 'd', 'args', 'kwargs', 'e')
        >>> print(func.__code__.co_argcount)    # `a` and `b`
        2
        >>> print(func.__code__.co_kwonlyargcount)  # `c` and `d`
        2
    """
    variable_names = func.__code__.co_varnames
    arg_count = func.__code__.co_argcount + func.__code__.co_kwonlyargcount

    return variable_names[:arg_count]
