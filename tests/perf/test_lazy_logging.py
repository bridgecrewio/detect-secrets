"""
Unit tests for lazy %-style log formatting in hot-path log calls (scan.py).

Rationale: `log.info(f'...{value}...')` builds the full string on EVERY call,
even when INFO-level logging is disabled (the default level is ERROR). Standard
`logging.Logger.info(msg, *args)` only performs %-substitution if the logger's
effective level actually processes the record — so passing a literal template
string plus separate positional args (instead of a pre-built f-string) avoids
that wasted work in the common case (INFO disabled).

These tests do NOT rely on the `mock_log` autouse fixture's MockLogWrapper
(which eagerly formats unconditionally in tests, for debuggability) — instead
they patch `scan_module.log` directly with a `MagicMock` so we can inspect the
*raw* call arguments. This directly proves whether the call site itself builds
an eager string (bad) or defers formatting to the logging call args (good).

TDD: write failing tests first, then implement.
"""
from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

from detect_secrets.core import scan as scan_module


def _make_filter(path, return_value=True):
    def fn(**kwargs):
        return return_value
    fn.path = path
    return fn


def test_is_filtered_out_secret_branch_uses_lazy_percent_style_logging():
    """The 'secret' branch of _is_filtered_out must log lazily via %s args."""
    filter_fn = _make_filter('my.filter.path')
    mock_logger = MagicMock()

    with patch.object(scan_module, 'get_filters_with_parameter', return_value=[filter_fn]), \
            patch.object(scan_module, 'log', mock_logger):
        result = scan_module._is_filtered_out(
            required_filter_parameters=['secret'],
            filename='foo.py',
            secret='sekret123',
            line='blah',
        )

    assert result is True
    mock_logger.info.assert_called_once()
    args = mock_logger.info.call_args[0]

    # First positional arg must be a literal template still containing '%s'
    # placeholders -- proving no eager f-string interpolation happened at the
    # call site itself.
    assert '%s' in args[0], (
        f'Expected lazy %-style template with placeholders, got: {args[0]!r}'
    )
    assert args[1:] == ('sekret123', 'my.filter.path')
    # Rendering the template against the args must reproduce the exact same
    # message as before the change (behavior parity).
    assert args[0] % args[1:] == 'Skipping "sekret123" due to `my.filter.path`.'


def test_is_filtered_out_filename_only_branch_uses_lazy_percent_style_logging():
    """The filename-only branch of _is_filtered_out must log lazily via %s args."""
    filter_fn = _make_filter('detect_secrets.filters.common.is_invalid_file')
    mock_logger = MagicMock()

    with patch.object(scan_module, 'get_filters_with_parameter', return_value=[filter_fn]), \
            patch.object(scan_module, 'log', mock_logger):
        result = scan_module._is_filtered_out(
            required_filter_parameters=['filename'],
            filename='test_data',
        )

    assert result is True
    mock_logger.info.assert_called_once()
    args = mock_logger.info.call_args[0]

    assert '%s' in args[0], (
        f'Expected lazy %-style template with placeholders, got: {args[0]!r}'
    )
    assert args[1:] == ('test_data', 'detect_secrets.filters.common.is_invalid_file')
    assert args[0] % args[1:] == (
        'Skipping "test_data" due to `detect_secrets.filters.common.is_invalid_file`'
    )


def test_is_filtered_out_generic_branch_uses_lazy_percent_style_logging():
    """The generic (neither secret nor sole-filename) branch must log lazily."""
    filter_fn = _make_filter('my.other.filter')
    mock_logger = MagicMock()

    with patch.object(scan_module, 'get_filters_with_parameter', return_value=[filter_fn]), \
            patch.object(scan_module, 'log', mock_logger):
        result = scan_module._is_filtered_out(
            required_filter_parameters=['context'],
            filename='foo.py',
            line='blah',
            context=None,
        )

    assert result is True
    mock_logger.info.assert_called_once()
    args = mock_logger.info.call_args[0]

    assert '%s' in args[0], (
        f'Expected lazy %-style template with placeholders, got: {args[0]!r}'
    )
    assert args[1:] == ('my.other.filter',)
    assert args[0] % args[1:] == 'Skipping secret due to `my.other.filter`.'


def test_get_lines_from_file_checking_message_uses_lazy_percent_style_logging(tmp_path):
    """`_get_lines_from_file` must log the 'Checking file' message lazily."""
    target_file = tmp_path / 'sample.txt'
    target_file.write_text('line one\nline two\n')

    mock_logger = MagicMock()
    with patch.object(scan_module, 'log', mock_logger):
        list(scan_module._get_lines_from_file(str(target_file)))

    mock_logger.info.assert_called_once()
    args = mock_logger.info.call_args[0]

    assert '%s' in args[0], (
        f'Expected lazy %-style template with placeholders, got: {args[0]!r}'
    )
    assert args[1:] == (str(target_file),)
    assert args[0] % args[1:] == f'Checking file: {target_file}'


def test_is_filtered_out_message_rendering_matches_original_output_for_real_logger():
    """
    End-to-end parity check using the real MockLogWrapper (mimics production
    logging.Logger %-substitution semantics): rendered messages must be
    byte-identical to what the original f-string implementation produced.
    """
    from testing.mocks import MockLogWrapper

    real_mock_log = MockLogWrapper()
    filter_fn = _make_filter('my.filter.path')

    with patch.object(scan_module, 'get_filters_with_parameter', return_value=[filter_fn]), \
            patch.object(scan_module, 'log', real_mock_log):
        scan_module._is_filtered_out(
            required_filter_parameters=['secret'],
            filename='foo.py',
            secret='sekret123',
            line='blah',
        )

    assert 'Skipping "sekret123" due to `my.filter.path`.' in real_mock_log.info_messages
