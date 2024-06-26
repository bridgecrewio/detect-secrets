import re
from functools import lru_cache
from typing import List
from typing import Pattern

from ..settings import get_settings
from .util import get_caller_path


def should_exclude_line(line: str) -> bool:
    regexes = _get_line_exclusion_regex()
    return any(regex.search(line) for regex in regexes)


@lru_cache(maxsize=1)
def _get_line_exclusion_regex() -> List[Pattern]:
    path = get_caller_path(offset=1)
    return [re.compile(regex) for regex in get_settings().filters[path]['pattern']]


def should_exclude_file(filename: str) -> bool:
    regexes = _get_file_exclusion_regex()
    return any(regex.search(filename) for regex in regexes)


@lru_cache(maxsize=1)
def _get_file_exclusion_regex() -> List[Pattern]:
    path = get_caller_path(offset=1)
    return [re.compile(regex) for regex in get_settings().filters[path]['pattern']]


def should_exclude_secret(secret: str) -> bool:
    regexes = _get_secret_exclusion_regex()
    return any(regex.search(secret) for regex in regexes)


@lru_cache(maxsize=1)
def _get_secret_exclusion_regex() -> List[Pattern]:
    path = get_caller_path(offset=1)
    return [re.compile(regex) for regex in get_settings().filters[path]['pattern']]
