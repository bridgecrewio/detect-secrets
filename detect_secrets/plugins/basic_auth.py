import re

from .base import RegexBasedDetector


# This list is derived from RFC 3986 Section 2.2.
#
# We don't expect any of these delimiter characters to appear in
# the username/password component of the URL, seeing that this would probably
# result in an unexpected URL parsing (and probably won't even work).
RESERVED_CHARACTERS = ':/?#[]@'
SUB_DELIMITER_CHARACTERS = '!$&\'()*+,;='


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
