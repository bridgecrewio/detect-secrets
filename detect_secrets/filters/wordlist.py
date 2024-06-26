"""
There may be known words that are definitely test keys (e.g. AKIATEST for AWS keys).
One way that we can filter these out is by passing in a list of words that we know
will result in false positives. This filter efficiently processes this through the
use of the Aho-Corasick algorithm.
"""
from functools import lru_cache
from typing import Any

from ..settings import get_settings
from .util import compute_file_hash


Automaton = Any


def is_feature_enabled() -> bool:
    try:
        get_automaton()
        return True
    except ImportError:
        return False


def initialize(wordlist_filename: str, min_length: int = 3, file_hash: str = '') -> Automaton:  #noqa: ARG001
    """
    :param min_length: if words are too small, the automaton will flag too many
        words. As a result, our recall will decrease without a precision boost.
        Tweak this value to customize it based on your own findings.

    :param file_hash: this is currently used for baseline reporting purposes only, rather than
        engine's functionality. One can imagine a future where this automaton model is
        cached and keyed off the hash, and thus, this file_hash can be used to see if the
        cache needs to be invalidated.

        But alas, this functionality has yet to be implemented.
    """
    # See https://pyahocorasick.readthedocs.io/en/latest/ for more information.
    automaton = get_automaton()
    with open(wordlist_filename) as f:
        for line in f.readlines():
            line = line.lower().strip()

            if len(line) < min_length:
                continue

            automaton.add_word(line, line)

    path = f'{__name__}.should_exclude_secret'
    get_settings().filters[path] = {
        'min_length': min_length,
        'file_name': wordlist_filename,
        'file_hash': compute_file_hash(wordlist_filename),
    }

    automaton.make_automaton()
    return automaton


def should_exclude_secret(secret: str) -> bool:
    try:
        # .lower() to make everything case-insensitive
        next(get_automaton().iter(string=secret.lower()))
        return True
    except StopIteration:
        return False


@lru_cache(maxsize=1)
def get_automaton() -> Automaton:
    import ahocorasick  # type:ignore[import-not-found]
    return ahocorasick.Automaton()
