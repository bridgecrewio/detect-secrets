import re
from typing import Any
from typing import Optional
from typing import Set

from .base import RegexBasedDetector
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.util.code_snippet import CodeSnippet


# This list is derived from RFC 3986 Section 2.2.
#
# We don't expect any of these delimiter characters to appear in
# the username/password component of the URL, seeing that this would probably
# result in an unexpected URL parsing (and probably won't even work).
RESERVED_CHARACTERS = ':/?#[]@'
SUB_DELIMITER_CHARACTERS = '!$&\'()*+,;='


class BasicAuthDetector(RegexBasedDetector):
    """Scans for Basic Auth formatted URIs."""
    secret_type = 'Basic Auth Credentials'

    denylist = [
        re.compile(
            r'://[^{}\s]+:([^{}\s]+)@'.format(
                re.escape(RESERVED_CHARACTERS + SUB_DELIMITER_CHARACTERS),
                re.escape(RESERVED_CHARACTERS + SUB_DELIMITER_CHARACTERS),
            ),
        ),
    ]

    def analyze_line(
            self,
            filename: str,
            line: str,
            line_number: int = 0,
            context: Optional[CodeSnippet] = None,
            raw_context: Optional[CodeSnippet] = None,
            **kwargs: Any,
    ) -> Set[PotentialSecret]:
        findings = super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            raw_context=raw_context,
            **kwargs,
        )

        # if any of the reserved "example" domains appears (case-insensitive), drop all findings
        lowered = line.lower()
        for domain in (
                'example.com', 'example.net', 'example.org', 'proxy.url', 'github.com/owner',
        ):
            if domain in lowered:
                return set()

        return findings
