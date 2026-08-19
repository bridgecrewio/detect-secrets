import pytest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import calculate_shannon_entropy
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString

# The short-circuit is enabled by default in the plugin, but we can be explicit for clarity
_ENTROPY_SC_ENABLED = True
_ENTROPY_MIN_LEN = 8
_ENTROPY_MIN_DISTINCT = 4

class TestEntropyShortCircuitCorrectness:

    def test_short_string_is_short_circuited(self):
        """
        Tests that a 7-character string, despite having high theoretical entropy,
        is short-circuited to 0.0 by the length check.
        """
        # 7 unique characters, max entropy for this length is log2(7) ~= 2.8
        high_entropy_short_string = 'ABCDEFG'
        plugin = HexHighEntropyString()

        # With short-circuit enabled, this should return 0.0
        entropy = calculate_shannon_entropy(
            high_entropy_short_string,
            plugin.charset,
        )
        assert entropy == 0.0

    def test_low_distinct_chars_is_short_circuited(self):
        """
        Tests that a long string with too few distinct characters is
        short-circuited to 0.0.
        """
        # String is > 8 chars, but only has 3 distinct characters ('a', 'b', 'c')
        low_distinct_char_string = 'ababababac'
        plugin = HexHighEntropyString()

        # With short-circuit enabled, this should return 0.0
        entropy = calculate_shannon_entropy(
            low_distinct_char_string,
            plugin.charset,
        )
        assert entropy == 0.0

    def test_hex_string_at_threshold_is_detected(self):
        """
        Tests that a valid high-entropy hex string, exactly at the length
        and entropy limit, is correctly identified as a secret.
        """
        # 8 unique chars, entropy is log2(8) = 3.0.
        # The Hex plugin limit is 3.0, so this should be caught.
        high_entropy_hex = 'ABCDEF01'
        line = f'secret = "{high_entropy_hex}"'

        plugin = HexHighEntropyString(limit=2.9)
        findings = plugin.analyze_line(
            'test.py',
            line,
            1,
        )

        assert len(findings) == 1
        assert list(findings)[0].secret_value == high_entropy_hex

    def test_hex_string_at_threshold_low_entropy_is_ignored(self):
        """
        Tests that a low-entropy hex string, at the length threshold but
        with low entropy, is correctly ignored.
        """
        # 8 chars, but entropy is 0.0
        low_entropy_hex = 'AAAAAAAA'
        line = f'version = "{low_entropy_hex}"'

        plugin = HexHighEntropyString(limit=3.0)
        findings = plugin.analyze_line(
            'test.py',
            line,
            1,
        )

        assert len(findings) == 0

    def test_entropy_limit_is_exclusive_not_inclusive(self):
        """
        Regression guard for the checkov CKV_SECRET_6 false positives.

        'admin123' has entropy of exactly 3.0, and checkov configures a limit of
        exactly 3. Comparing with >= instead of > flags it as a secret, which broke
        the checkov CI on unrelated PRs. The comparison must stay exclusive.
        """
        plugin = Base64HighEntropyString(limit=3)

        assert plugin.calculate_shannon_entropy('admin123') == 3.0
        assert plugin.analyze_line('test.py', 'password = "admin123"', 1) == set()

    def test_base64_string_at_threshold_is_detected(self):
        """
        Tests that a valid high-entropy base64 string, just above the length
        threshold, is correctly identified as a secret.
        """
        # 8 unique base64 chars. Entropy is log2(8) = 3.0.
        # This is below the default base64 limit of 4.5, so it should NOT be flagged.
        medium_entropy_base64 = 'a+b/C&D='
        line_med = f'secret = "{medium_entropy_base64}"'

        # 11 unique base64 chars. Entropy is log2(11) ~= 3.45. Still below 4.5
        medium_entropy_base64_2 = 'a+b/C&D=E$F'
        line_med_2 = f'secret = "{medium_entropy_base64_2}"'

        # 24 unique base64 chars. Entropy is log2(24) ~= 4.58, which is > 4.5
        high_entropy_base64 = 'ABCDEFGHIJKLMNOPQRSTUVWX'
        line_high = f'secret = "{high_entropy_base64}"'

        plugin = Base64HighEntropyString(limit=4.5)

        # Test the medium entropy strings (should not be found)
        findings_med = plugin.analyze_line('test.py', line_med, 1)
        assert len(findings_med) == 0

        findings_med_2 = plugin.analyze_line('test.py', line_med_2, 1)
        assert len(findings_med_2) == 0

        # Test the high entropy string (should be found)
        findings_high = plugin.analyze_line('test.py', line_high, 1)
        assert len(findings_high) == 1
        assert list(findings_high)[0].secret_value == high_entropy_base64
