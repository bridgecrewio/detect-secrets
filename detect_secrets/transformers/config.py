"""
This handles `.ini` files, or more generally known as `config` files.
"""
import configparser
import re
from typing import Iterator
from typing import List
from typing import Tuple

from ..custom_types import NamedIO
from ..util.filetype import determine_file_type
from ..util.filetype import FileType
from .base import BaseTransformer
from .exceptions import ParsingError
from detect_secrets.filters.allowlist import get_allowlist_regexes


class ConfigFileTransformer(BaseTransformer):
    def should_parse_file(self, filename: str) -> bool:
        return True

    def parse_file(self, file: NamedIO) -> List[str]:
        try:
            return _parse_file(file)
        except configparser.Error:
            raise ParsingError


class EagerConfigFileTransformer(BaseTransformer):
    # NOTE: Currently eager, since `determine_file_type` is minimalistic right now.
    is_eager = True

    def should_parse_file(self, filename: str) -> bool:
        return determine_file_type(filename) == FileType.OTHER

    def parse_file(self, file: NamedIO) -> List[str]:
        try:
            return _parse_file(file, add_header=True)
        except configparser.Error:
            raise ParsingError


def _parse_file(file: NamedIO, add_header: bool = False) -> List[str]:
    """
    :raises: configparser.Error
    :raises: UnicodeDecodeError
    """
    lines: List[str] = []
    for key, value, line_number in IniFileParser(file, add_header=add_header):
        while len(lines) < line_number - 1:
            lines.append('')

        # Always add 'pragma: allowlist nextline secret' comments
        if _is_allowlist_nextline_secret_comment(value):
            lines.append(value)
            continue

        # We artificially add quotes here because we know they are strings
        # (because it's a config file), HighEntropyString will benefit from this,
        # and all other plugins don't care.
        if value[0] in {"'", '"'} and value[-1] == value[0]:
            # Strip out quotes, because we'll add our own.
            value = value[1:-1]

        value = value.replace('"', '\\"')
        lines.append(f'{key} = "{value}"')

    return lines


class EfficientParsingError(configparser.ParsingError):

    def append(self, lineno: int, line: str) -> None:
        """
        Rather than inefficiently add all the lines in the file
        to the error message like the CPython code from 1998,
        we just `return` because we will catch and `pass`
        the exception in `high_entropy_strings.py` anyway.
        """
        return


configparser.ParsingError = EfficientParsingError       # type: ignore


class IniFileParser:

    _comment_regex = re.compile(r'\s*[;#]')

    def __init__(self, file: NamedIO, add_header: bool = False) -> None:
        """
        :param add_header: whether or not to add a top-level [global] header.
        """
        self.parser = configparser.ConfigParser()
        self.parser.optionxform = str  # type: ignore

        content = file.read()
        if add_header:
            # This supports environment variables, or other files that look
            # like config files, without a section header.
            content = '[global]\n' + content

        self.parser.read_string(content)

        # Hacky way to keep track of line location
        file.seek(0)
        self.lines = [line.strip() for line in file.readlines()]
        self.line_offset = 0

    def __iter__(self) -> Iterator[Tuple[str, str, int]]:
        if not self.parser.sections():
            # To prevent cases where it's not an ini file, but the parser
            # helpfully attempts to parse everything to a DEFAULT section,
            # when not explicitly provided.
            raise configparser.Error

        for section_name in self.parser:
            for key, values in self.parser.items(section_name):
                for value, offset in self._get_value_and_line_offset(key, values):
                    if not value:
                        continue

                    yield key, value, offset

    def _get_value_and_line_offset(self, key: str, values: str) -> List[Tuple[str, int]]:
        """Returns the index of the location of key, value pair in lines.

        :param key: key, in config file.
        :param values: values for key, in config file. This is plural,
            because you can have multiple values per key. e.g.

            >>> key =
            ...     value1
            ...     value2
        """
        values_list = _construct_values_list(values)
        if not values_list:
            return []

        current_value_list_index = 0
        output = []

        for line_offset, line in enumerate(self.lines):
            # Check 'pragma: allowlist nextline secret' comment on a single line
            # The IniFileParser strips out comments however it is important to
            # persist this speific comment type so filtering works properly.
            if _is_allowlist_nextline_secret_comment(line):
                output.append((
                    line,
                    self.line_offset + line_offset + 1,
                ))
                continue

            # Check ignored lines before checking values, because
            # you can write comments *after* the value.
            if not line or self._comment_regex.match(line):
                continue

            # The first line is special because it's the only one with the variable name.
            # As such, we should handle it differently.
            if current_value_list_index == 0:
                # In situations where the first line does not have an associated value,
                # it will be an empty string. However, this regex still does its job because
                # it's not necessarily the case where the first line is a non-empty one.
                #
                # Therefore, we *only* advance the current_value_list_index when we identify
                # the key used.
                first_line_regex = re.compile(
                    r'^\s*{key}[ :=]+{value}'.format(
                        key=re.escape(key),
                        value=re.escape(values_list[current_value_list_index]),
                    ),
                )
                if first_line_regex.match(line):
                    output.append((
                        values_list[current_value_list_index],
                        self.line_offset + line_offset + 1,
                    ))
                    current_value_list_index += 1

                continue

            # There's no more values to iterate over.
            if current_value_list_index == len(values_list):
                if line_offset == 0:
                    line_offset = 1  # Don't want to count the same line again

                self.line_offset += line_offset
                self.lines = self.lines[line_offset:]

                break

            # This handles all other cases, when it isn't an empty or blank line.
            output.append((
                values_list[current_value_list_index],
                self.line_offset + line_offset + 1,
            ))
            current_value_list_index += 1
        else:
            self.lines = []

        return output


def _construct_values_list(values: str) -> List[str]:
    """
    This values_list is a strange construction, because of ini format.
    We need to extract the values with the following supported format:

        >>> key = value0
        ...     value1
        ...
        ...     # Comment line here
        ...     value2

    given that normally, either value0 is supplied, or (value1, value2),
    but still allowing for all three at once.

    Furthermore, with the configparser, we will get a list of values,
    and intermediate blank lines, but no comments. This means that we can't
    merely use the count of values' items to heuristically "skip ahead" lines,
    because we still have to manually parse through this.

    Therefore, we construct the values_list in the following fashion:
        1. Keep the first value (in the example, this is `value0`)
        2. For all other values, ignore blank lines.
    Then, we can parse through, and look for values only.
    """
    lines = values.splitlines()
    values_list = lines[:1]
    values_list.extend(filter(None, lines[1:]))
    return values_list


def _is_allowlist_nextline_secret_comment(line: str) -> bool:
    # Valid tuples for config file comments (start_char, end_char)
    comment_tuple = [('#', ''), (';', '')]

    for t in comment_tuple:
        if get_allowlist_regexes(comment_tuple=t, nextline=True).search(line):
            return True

    return False
