import textwrap
from unittest import mock

import pytest

from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import get_secret_access_keys
from detect_secrets.util.code_snippet import get_code_snippet


EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


class TestAWSKeyDetector:

    def setup_method(self):
        self.example_key = 'AKIAZZZZZZZZZZZZZZZZ'

    @pytest.mark.parametrize(
        'line,should_flag',
        [
            (
                'AKIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'akiazzzzzzzzzzzzzzzz',
                False,
            ),
            (
                'AKIAZZZ',
                False,
            ),
            (
                'A3T0ZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ABIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ACCAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ASIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET),
                True,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET + 'a'),
                False,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET[0:39]),
                False,
            ),
            (
                '/9n/7QoAUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAAccAgAAAgACADhCSU0EJQAAAAAAEEYM8okmuFbasJwBobCnkHc4QklNA+0AAAAAABAASAAAAAEAAQBIAAAAAQABOEJJTQQmAAAAAAAOAAAAAAAAAAAAAD+AAAA4QklNBA0AAAAAAAQAAAB4OEJJTQQZAAAAAAAEAAAAHjhCSU0D8wAAAAAACQAAAAAAAAAAAQA4QklNBAoAAAAAAAEAADhCSU0nEAAAAAAACgABAAAAAAAAAAI4QklNA/QAAAAAABIANQAAAAEALQAAAAYAAAAAAAE4QklNA/cAAAAAABwAAP////////////////////////////8D6AAAOEJJTQQIAAAAAAAQAAAAAQAAAkAAAAJAAAAAADhCSU0EHgAAAAAABAAAAAA4QklNBBoAAAAAA00AAAAGAAAAAAAAAAAAAAD9AAABTgAAAAwAQwBvAG4AZgBpAGQAZQBuAHQAaQBhAGwAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAU4AAAD9AAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAEAAAAAAABudWxsAAAAAgAAAAZib3VuZHNPYmpjAAAAAQAAAAAAAFJjdDEAAAAEAAAAAFRvcCBsb25nAAAAAAAAAABMZWZ0bG9uZwAAAAAAAAAAQnRvbWxvbmcAAAD9AAAAAFJnaHRsb25nAAABTgAAAAZzbGljZXNWbExzAAAAAU9iamMAAAABAAAAAAAFc2xpY2UAAAASAAAAB3NsaWNlSURsb25nAAAAAAAAAAdncm91cElEbG9uZwAAAAAAAAAGb3JpZ2luZW51bQAAAAxFU2xpY2VPcmlnaW4AAAANYXV0b0dlbmVyYXRlZAAAAABUeXBlZW51bQAAAApFU2xpY2VUeXBlAAAAAEltZyAAAAAGYm91bmRzT2Jq',
                False,
            ),
            (
                f'AWS_SECRET_ACCESS_KEY={EXAMPLE_SECRET}\n',
                True,
            ),
        ],
    )
    def test_analyze(self, line, should_flag):
        logic = AWSKeyDetector()

        output = logic.analyze_line(filename='mock_filename', line=line)
        assert len(output) == (1 if should_flag else 0)

    def test_verify_no_secret(self):
        logic = AWSKeyDetector()

        assert logic.verify(
            self.example_key,
            get_code_snippet([], 1),
        ) == VerifiedResult.UNVERIFIED

        assert logic.verify(
            EXAMPLE_SECRET,
            get_code_snippet([], 1),
        ) == VerifiedResult.UNVERIFIED

    def test_verify_valid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=True,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.VERIFIED_TRUE

    def test_verify_invalid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=False,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.VERIFIED_FALSE

    def test_verify_keep_trying_until_found_something(self):
        data = {'count': 0}

        def counter(*args, **kwargs):
            output = data['count']
            data['count'] += 1

            return bool(output)

        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            counter,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(
                    [
                        f'false_secret = {"TEST" * 10}',
                        f'real_secret = {EXAMPLE_SECRET}',
                    ],
                    1,
                ),
            ) == VerifiedResult.VERIFIED_TRUE


@pytest.mark.parametrize(
    'content, expected_output',
    (
        # Assignment with no quotes
        (
            textwrap.dedent("""
                aws_secret_access_key = {}
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with no quotes
        (
            textwrap.dedent("""
                some_function({})
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with comma and no quotes
        (
            textwrap.dedent("""
                some_function(foo, {}, bar)
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # With quotes
        (
            textwrap.dedent("""
                secret_key = "{}"
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with quotes
        (
            textwrap.dedent("""
                some_function("{}")
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with comma and quotes
        (
            textwrap.dedent("""
                some_function('foo', '{}', 'bar')
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Multiple assignment with quotes candidates
        (
            textwrap.dedent("""
                base64_keyA = '{}'
                aws_secret = '{}'
                base64_keyB = '{}'
            """)[1:-1].format(
                'TEST' * 10,

                EXAMPLE_SECRET,

                # This should not be a candidate, because it's not exactly
                # 40 chars long.
                'EXAMPLE' * 7,
            ),
            [
                'TEST' * 10,
                EXAMPLE_SECRET,
            ],
        ),
    ),
)
def test_get_secret_access_key(content, expected_output):
    assert get_secret_access_keys(
        get_code_snippet(content.splitlines(), 1),
    ) == expected_output
