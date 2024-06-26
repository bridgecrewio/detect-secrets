from __future__ import annotations

import argparse
import os
from typing import cast
from typing import Iterable

from .. import plugins
from ...exceptions import InvalidFile
from ...settings import get_settings
from ..plugins.util import get_mapping_from_secret_type_to_class


def add_plugin_options(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='plugin options',
        description=(
            'Configure settings for each secret scanning '
            'ruleset. By default, all plugins are enabled '
            'unless explicitly disabled.'
        ),
    )

    parser.add_argument(
        '--list-all-plugins',
        action='store_true',
        help='Lists all plugins that will be used for the scan.',
    )

    _add_custom_plugins(parser)
    _add_custom_limits(parser)
    _add_disable_flag(parser)


def _add_custom_plugins(parser: argparse._ArgumentGroup) -> None:
    def valid_looking_paths(path: str) -> str:
        # We can verify whether these files are valid at post-processing.
        # TODO: support directories
        # TODO: support selecting specific classes in files.
        # TODO: do we also want to overload this and allow specific selection of plugins for
        # baselines that don't currently use those plugins?
        if not os.path.isfile(path):
            raise argparse.ArgumentTypeError(f'{path} is not a valid file.')

        return path

    parser.add_argument(
        '-p',
        '--plugin',
        type=valid_looking_paths,
        nargs=1,
        action='append',        # so we can support multiple flags with same value
        help='Specify path to custom secret detector plugin.',
    )


def _add_custom_limits(parser: argparse._ArgumentGroup) -> None:
    def minmax_type(string: str) -> float:
        value = float(string)
        if value < 0 or value > 8:
            raise argparse.ArgumentTypeError(
                f'{string} must be between 0.0 and 8.0',
            )

        return value

    high_entropy_help_text = (
        'Sets the entropy limit for high entropy strings. '
        'Value must be between 0.0 and 8.0,'
    )

    # NOTE: This doesn't have explicit default values since we want to be able to determine
    # the difference between a value set by default, and an explicitly set value (which happens
    # to be the same as the default value). This distinction plays an important role when doing
    # precedence calculation (default value < baseline config < CLI explicit value)
    parser.add_argument(
        '--base64-limit',
        type=minmax_type,
        nargs='?',
        help=high_entropy_help_text + ' defaults to 4.5.',
    )
    parser.add_argument(
        '--hex-limit',
        type=minmax_type,
        nargs='?',
        help=high_entropy_help_text + ' defaults to 3.0.',
    )


def _add_disable_flag(parser: argparse._ArgumentGroup) -> None:
    def valid_plugin_name(string: str) -> str:
        valid_plugin_names: set[str] = {
            item.__name__
            for item in get_mapping_from_secret_type_to_class().values()
        }

        if string not in valid_plugin_names:
            raise argparse.ArgumentTypeError(f'Invalid plugin classname: {string}')

        return string

    parser.add_argument(
        '--disable-plugin',
        type=valid_plugin_name,
        nargs=1,
        action='append',        # so we can support multiple flags with the same value
        help='Plugin class names to disable. e.g. Base64HighEntropyString',
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.disable_plugin:
        # Flatten entry for easier parsing.
        args.disable_plugin = {entry for item in args.disable_plugin for entry in item}
        get_settings().disable_plugins(*args.disable_plugin)

    # By the time the code reaches here, the baseline logic will have populated an initial
    # state for settings. Therefore, this will override whatever state that is currently registered.
    #
    # Default values will be applied at the plugin level.
    if args.base64_limit:
        get_settings().plugins['Base64HighEntropyString']['limit'] = args.base64_limit

    if args.hex_limit:
        get_settings().plugins['HexHighEntropyString']['limit'] = args.hex_limit

    if args.plugin:
        # Flatten entry for easier parsing.
        args.plugin = [entry for item in args.plugin for entry in item]

        for filename in args.plugin:
            # NOTE: Technically, we could just configure the settings, and have
            # `detect_secrets.core.plugins.util.get_mapping_from_secret_type_to_class`
            # to initialize them. However, if it's in the baseline / settings, we can
            # assume it works -- therefore, let's initialize it to discover any errors early
            # on, before storing it in settings.
            try:
                custom_plugins = cast(Iterable, plugins.initialize.from_file(filename))
            except InvalidFile:
                raise argparse.ArgumentTypeError(f'Cannot load plugins from {filename}.')

            get_settings().configure_plugins([
                {
                    'name': item.__name__,
                    'path': f'file://{os.path.abspath(filename)}',
                }
                for item in custom_plugins
            ])
