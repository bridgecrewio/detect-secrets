import json

import pytest

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


@pytest.mark.parametrize(
    'file_content, secrets_amount, expected_secret',
    [
        (
            json.dumps(
                '-----BEGIN RSA PRIVATE KEY-----\n'
                'c3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZ\n'
                'WNyZXQgcGFzc3dvcmQhMTIzNCMkJQpzdXBlciBkdXBlciBzZWNyZXQgcGFzc3'
                'dvcmQsIHN1cGVyIGR1cGVyIHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=\n'
                '-----END RSA PRIVATE KEY-----',
            ),
            1,
            '\\nc3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZ\\n'
            'WNyZXQgcGFzc3dvcmQhMTIzNCMkJQpzdXBlciBkdXB'
            'lciBzZWNyZXQgcGFzc3dvcmQsIHN1cGVyIGR1cGVyIHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=',
        ),
        (
            'some text here\n'
            '-----BEGIN PRIVATE KEY-----\n'
            'c3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZWNyZXQgcGFzc3'
            'dvcmQhMTIzNCMkJQpzdXBlciBkdXBlciBzZWNyZXQgcGFzc3dvcmQsIHN1cGVyIGR1cGVy'
            'IHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=\n'
            '-----END PRIVATE KEY-----',
            1,
            'c3VwZXIgZHVwZXIgc2VjcmV0IHBhc3N3b3JkLCBzdXBlciBkdXBlciBzZWNyZXQgcGFzc3'
            'dvcmQhMTIzNCMkJQpzdXBlciBkdXBlciBzZWNyZXQgcGFzc3dvcmQsIHN1cGVyIGR1cGVy'
            'IHNlY3JldCBwYXNzd29yZCExMjM0IyQlCgo=',
        ),
        (
            'some text here\n'
            'PuTTY-User-Key-File-2: ssh-rsa\n'
            'Encryption: none\n'
            'Comment: imported-openssh-key\n'
            'Public-Lines: 6\n'
            'AAAAEXAMPLEyc2EAAAADAQABAAABAQCuCEcRjgR7fUnMhGqyRz+e7pWhS6a6LTLl\n'
            'CO8skSsi0sZCy6bMdefB6X6HHnT43UXh7QJH6hqwE2m9rXAGoEJV9nVMIQnK2077\n'
            '48hLCj1EC4ykPxmeTu2LVtsxm8ev+8ji6vYCn1RATBhvmKruURKKvQ2+W8ojPFIk\n'
            'VyQD8g2PeL0i3XwJlX50NstF9JCayAvPIw9r4mvQvtdpyio5DxCtCYZ3FRxPFaSC\n'
            '3KAXXer6KzBpbhxPRBKW/EryFADtlOi5ajzVK/rs8IiUlE3UyNKVNYAcx+eRjYPa\n'
            'ffok0QMuI7wnwfC/ni+qzE/SezXGdxqDBoOF9aWK60CT5zt0c+qP\n'
            'Private-Lines: 14\n'
            'AAABAEmdgsJwOoEqDC+Qy7lB3i2SaoTiBVK3j9HGJ7XIamC+m9LhZlsSfMhPxo/N\n'
            'WFl07/yTTuWwpz1X2OC9HqgO3kCSkidzyjqe7hgq0Cy91hCUehd4AZQvetf4E5w2\n'
            'cw+ECAPEs++EChVwmt2JzLQmYxuAwPGGzkh9WZm5qqhomUfYbCucBzqr5I4XCrlN\n'
            'VbuU7nD7j5hbybigy26SLVRpqMJKX13uLUgInMUCNjOYD77dExIMS6CvUfro0kB+\n'
            'v6+TmsU+GzzWdJpk6xf6TkrzE7+VppZf6NwSu+9SKltBfh8uwvGuIjlDxgt5oISS\n'
            'mIn0t38K/nE9fTc4jlAGGNoCIZEAAACBAPYVDoY0sT0w7mhhOxKVGDYnwfqAKF5V\n'
            '+45hM9O7L0UR+piPrNnkhie5xBkUCE+XiGwpbjVb+AJXQHW4RIVh0/GpWX4SZ/ti\n'
            'ceUUYDn7bkMr+KiI47eIHbEmt9vsp7iD2ylgimLjt8V3RaGarDJjME7/0yUyrjmD\n'
            'eZR8Lh4FfWO1AAAAgQC1C9lQTiF8sk3dNgZjU2+BrPmvurvmGX/3BKguDrMbmISB\n'
            'tZA725ef+P7c1zWWcgzHnpXt9acEgCDGMsO3U8yKwJD9dGK6CLLIGSbG/NH5kLYu\n'
            'sjaHp4R4rvPZuQ714sWzQuBFJtj+g9UsmaENSDnomoEN3y7V3m0iFhgTLqBHswAA\n'
            'AIAuI6dYrQYrebrwurjnQBCxZS6/Vtcz2J1vwlfeRGe4GhFY0gc8yX88ZpGzCYl/\n'
            '3ERdiqVyiAjoGV1HkWjSe+HUzFVyB0r6mwcfcbaYVINsIThvzTU6SMVp1cbzbg21\n'
            'HqVFSq4s8HzsMnoj3oXusUHK9nE2JXTmVzEiZpZn33vuuA==\n'
            'Private-MAC: 4e0b0af986e3aef29b545fd4736949966be88af1',
            1,
            'PuTTY-User-Key-File-2: ssh-rsa\n'
            'Encryption:',
        ),
        (
            'lines.unshift("PuTTY-User-Key-File-2: " + alg);',
            0,
            None,
        ),
    ],
)
def test_basic(file_content, secrets_amount, expected_secret):
    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

        if secrets_amount == 0:
            assert len(secrets.files) == 0
        else:
            temp_file = list(secrets.files)[0]
            assert len(list(secrets)) == secrets_amount
            assert list(secrets.data[temp_file])[0].secret_value == expected_secret


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [{'name': 'PrivateKeyDetector'}],
    }):
        yield
