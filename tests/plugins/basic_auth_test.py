import pytest

from detect_secrets.plugins.basic_auth import BasicAuthDetector


class TestBasicAuthDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('https://username:password@yelp.com', True),
            ('http://localhost:5000/<%= @variable %>', False),
            ('"https://url:8000";@something else', False),
            ('\'https://url:8000\';@something else', False),
            ('https://url:8000 @something else', False),
            ('https://url:8000/ @something else', False),
            ('https://username:password@example.com', False),
            ('If the proxy requires authentication, a username and password must be included in the proxy URL. For example, `https://username:password@proxy.url:port`.', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = BasicAuthDetector()

        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
