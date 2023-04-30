from typing import Generator
from typing import Union
from typing import Any
from typing import Set

import requests

from ..constants import VerifiedResult
from .base import RegexBasedDetector
from .high_entropy_strings import Base64HighEntropyString
from ..core.potential_secret import PotentialSecret


class IbmCloudIamDetector(RegexBasedDetector):
    """Scans for IBM Cloud IAM Key."""

    secret_type = 'IBM Cloud IAM Key'
    # opt means optional
    opt_ibm_cloud_iam = r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|' + \
        r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)'
    opt_dash_underscore = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-zA-Z0-9_\-]{44}(?![a-zA-Z0-9_\-]))'
    denylist = [
        RegexBasedDetector.build_assignment_regex(
            prefix_regex=opt_ibm_cloud_iam + opt_dash_underscore + opt_api,
            secret_keyword_regex=key_or_pass,
            secret_regex=secret,
        ),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.high_entropy_plugin = Base64HighEntropyString()

    def verify(self, secret: str) -> VerifiedResult:
        response = verify_cloud_iam_api_key(secret)

        return VerifiedResult.VERIFIED_TRUE if response.status_code == 200 \
            else VerifiedResult.VERIFIED_FALSE

    def analyze_line(
            self,
            filename: str,
            line: str,
            **kwargs: Any
    ) -> Set[PotentialSecret]:
        """This examines a line and finds all possible secret values in it."""
        return {
            o for o in super().analyze_line(filename, line, **kwargs) if
            o.secret_value and self.high_entropy_plugin.is_entropy_valid(o.secret_value)
        }

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for match in RegexBasedDetector.analyze_string(self, string):
            entropy_result = self.high_entropy_plugin.calculate_shannon_entropy(match)
            if entropy_result > self.high_entropy_plugin.entropy_limit:
                yield match


def verify_cloud_iam_api_key(apikey: Union[str, bytes]) -> requests.Response:  # pragma: no cover
    if type(apikey) == bytes:
        apikey = apikey.decode('UTF-8')

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    response = requests.post(
        'https://iam.cloud.ibm.com/identity/token',
        headers=headers,
        data={
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': apikey,
        },
    )
    return response
