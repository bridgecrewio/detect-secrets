from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Type

from ...plugins.base import BasePlugin
from ...settings import get_settings
from ..log import log
from .util import get_mapping_from_secret_type_to_class
from .util import get_plugins_from_file
from .util import Plugin


def from_secret_type(secret_type: str) -> BasePlugin:
    """
    :raises: TypeError
    """
    try:
        plugin_type = get_mapping_from_secret_type_to_class()[secret_type]
    except KeyError:
        raise TypeError

    try:
        return plugin_type(**_get_config(plugin_type.__name__))
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise


def from_plugin_classname(classname: str) -> BasePlugin:
    """
    :raises: TypeError
    """
    for plugin_type in get_mapping_from_secret_type_to_class().values():
        if plugin_type.__name__ == classname:
            break
    else:
        log.error(f'Error: No such `{classname}` plugin to initialize.')
        log.error('Chances are you should run `pre-commit autoupdate`.')
        log.error(
            'This error can occur when using a baseline that was made by '
            'a newer detect-secrets version than the one running.',
        )
        raise TypeError

    try:
        return plugin_type(**_get_config(classname))
    except TypeError:
        log.error('Unable to initialize plugin!')
        raise


def from_file(filename: str) -> Iterable[Type[Plugin]]:
    """
    :raises: FileNotFoundError
    :raises: InvalidFile
    """
    output: List[Type[Plugin]] = []
    plugin_class: Type[Plugin]
    for plugin_class in get_plugins_from_file(filename):
        secret_type = plugin_class.secret_type  # type: ignore
        if secret_type in get_mapping_from_secret_type_to_class():
            log.info(f'Duplicate plugin detected: {plugin_class.__name__}. Skipping...')

        get_mapping_from_secret_type_to_class()[secret_type] = plugin_class
        output.append(plugin_class)

    return output


def _get_config(classname: str) -> Dict[str, Any]:
    output = {**get_settings().plugins.get(classname, {})}

    # External plugins use this key to specify the source. However, this key is not an
    # initialization variable. Therefore, let's remove it when initializing this config.
    if 'path' in output:
        output.pop('path')

    return output
