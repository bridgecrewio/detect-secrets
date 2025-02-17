"""
This plugin finds JWT tokens
"""
import base64
import json
import re
from typing import Generator

from .base import RegexBasedDetector


class JwtTokenDetector(RegexBasedDetector):
    """Scans for JWTs."""
    secret_type = 'JSON Web Token'
    denylist = [
        re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
    ]

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        yield from filter(
            self.is_formally_valid,
            super().analyze_string(string),
        )

    @staticmethod
    def is_formally_valid(token: str) -> bool:
        parts = token.split('.')
        for idx, part_str in enumerate(parts):
            try:
                part = part_str.encode('ascii')
                # https://github.com/magical/jwt-python/blob/2fd976b41111031313107792b40d5cfd1a8baf90/jwt.py#L49
                # https://github.com/jpadilla/pyjwt/blob/3d47b0ea9e5d489f9c90ee6dde9e3d9d69244e3a/jwt/utils.py#L33
                m = len(part) % 4
                if m == 1:
                    raise TypeError('Incorrect padding')
                elif m == 2:
                    part += b'=='
                elif m == 3:
                    part += b'==='
                b64_decoded = base64.urlsafe_b64decode(part)
                if idx < 2:
                    _ = json.loads(b64_decoded.decode('utf-8'))
            except (TypeError, ValueError, UnicodeDecodeError):
                return False

        return True
