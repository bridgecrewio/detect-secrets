import json
from unittest import mock

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


def test_private_key_line_number():
    file_content = '\n'.join([
        'Irrelevant line 1',
        'Irrelevant line 2',
        'Irrelevant line 3',
        'Irrelevant line 4',
        'Irrelevant line 5',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIBVwIBADANBgkqhkiG9w0BAQEFAASC',
        '-----END RSA PRIVATE KEY-----',
        'Some trailing text',
    ])

    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

        assert len(list(secrets)) == 1

        temp_file = list(secrets.files)[0]
        secret_obj = list(secrets.data[temp_file])[0]

        assert secret_obj.line_number == 7, (
            f'Expected the private key header to be detected at line 7, '
            f'but got {secret_obj.line_number} instead.'
        )


def test_private_key_line_number_2():
    file_content = '\n'.join([
        'Irrelevant line 1',
        'Irrelevant line 2',
        'Irrelevant line 3',
        'Irrelevant line 4',
        'Irrelevant line 5',
        '-----BEGIN RSA PRIVATE KEY-----MIIBVwIBADANBgkqhkiG9w0BAQEFAASC-----END RSA PRIVATE KEY-----',
        'Some trailing text',
    ])

    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

        assert len(list(secrets)) == 1

        temp_file = list(secrets.files)[0]
        secret_obj = list(secrets.data[temp_file])[0]

        assert secret_obj.line_number == 6, (
            f'Expected the private key header to be detected at line 6, '
            f'but got {secret_obj.line_number} instead.'
        )


def test_get_file_size_is_called_at_most_once_per_file():
    """Regression test for a performance bug.

    ``PrivateKeyDetector.analyze_line`` runs once per line. It must not perform
    a filesystem ``getsize`` lookup on every line: for a file larger than
    ``MAX_FILE_SIZE`` (which is never added to the ``_analyzed_files`` cache),
    the size lookup used to fire once per line, making the cost scale with
    (files x lines) instead of (files). This test proves the file-size lookup
    happens at most once for the whole file.
    """
    # Build a file that is well over MAX_FILE_SIZE (8 KiB) and has many lines,
    # none of which contain a private key.
    line = 'this is a perfectly ordinary line with no secrets in it at all'
    file_content = '\n'.join(line for _ in range(500))
    assert len(file_content.encode()) > (8 * 1024)

    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        with mock.patch(
            'detect_secrets.plugins.private_key.os.path.getsize',
            wraps=__import__('os').path.getsize,
        ) as mock_getsize:
            secrets = SecretsCollection()
            secrets.scan_file(f.name)

        assert mock_getsize.call_count <= 1, (
            f'Expected the private-key file-size lookup to run at most once per '
            f'file, but it ran {mock_getsize.call_count} times.'
        )


def test_multiline_private_key_in_small_file_is_still_detected():
    """Guards the file-size fix.

    The size lookup was hoisted to run once per file, and the per-file content
    read now happens exactly once. This confirms the whole-file read path still
    fires for a small file, so a private key split across multiple lines (which
    only matches when the full file content is scanned) is still detected.
    """
    file_content = '\n'.join([
        'Irrelevant line',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIBVwIBADANBgkqhkiG9w0BAQEFAASC',
        '-----END RSA PRIVATE KEY-----',
    ])
    assert len(file_content.encode()) < (8 * 1024)

    with mock_named_temporary_file() as f:
        f.write(file_content.encode())
        f.seek(0)

        secrets = SecretsCollection()
        secrets.scan_file(f.name)

    assert len(list(secrets)) == 1


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [{'name': 'PrivateKeyDetector'}],
    }):
        yield
