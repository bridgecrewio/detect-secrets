import pytest

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings


class TestDiff:
    def test_example(self):
        with transient_settings({
            'plugins_used': [
                {'name': 'HexHighEntropyString'},
                {'name': 'AWSKeyDetector'}
            ],
            'filters_used': [],
        }) as settings:
            settings.filters = {}
            secrets = SecretsCollection()
            with open('test_data/add_sample.diff') as f:
                secrets.scan_diff(f.read())

        assert secrets.files == {
            'detect_secrets/constants.py',
        }

