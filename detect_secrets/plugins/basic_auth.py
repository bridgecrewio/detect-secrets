import re
from detect_secrets.core.potential_secret import PotentialSecret

from .base import RegexBasedDetector


# This list is derived from RFC 3986 Section 2.2.
#
# We don't expect any of these delimiter characters to appear in
# the username/password component of the URL, seeing that this would probably
# result in an unexpected URL parsing (and probably won't even work).
RESERVED_CHARACTERS = ':/?#[]@'
SUB_DELIMITER_CHARACTERS = '!$&\'()*+,;='

# skip markdown, css, storyboard, and xib files
SKIP_EXTENSIONS = ('.md', '.css', '.storyboard', '.xib')


class BasicAuthDetector(RegexBasedDetector):
    """Scans for Basic Auth formatted URIs, but skips example.com."""
    secret_type = 'Basic Auth Credentials'

    denylist = [
        re.compile(
            r'://'
            r'[^{}\s]+:'                # username
            r'[^{}\s]+'                 # password
            r'@(?!example\.com\b)'      # negative lookahead
            .format(
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
            **kwargs,
    ) -> set[PotentialSecret]:
        # skip some noisy file types
        if filename and filename.lower().endswith(SKIP_EXTENSIONS):
            return set()
        # otherwise proceed as normal
        return super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            **kwargs,
        )
