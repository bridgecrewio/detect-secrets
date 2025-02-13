"""
This plugin searches for Slack tokens
"""
import re
from typing import Any
from typing import cast
from typing import Dict

import requests

from ..constants import VerifiedResult
from .base import RegexBasedDetector


class SlackDetector(RegexBasedDetector):
    """Scans for Slack tokens."""
    secret_type = 'Slack Token'

    denylist = [
        # Slack Token
        re.compile(r'xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+', flags=re.IGNORECASE),
    ]

    def verify(self, secret: str) -> VerifiedResult:  # pragma: no cover
        response = requests.post(
            'https://slack.com/api/auth.test',
            data={
                'token': secret,
            },
        ).json()
        valid = cast(Dict[str, Any], response)['ok']

        return (
            VerifiedResult.VERIFIED_TRUE
            if valid
            else VerifiedResult.VERIFIED_FALSE
        )
