import pytest

from detect_secrets.plugins.basic_auth import BasicAuthDetector


class TestBasicAuthDetector:

    @pytest.mark.parametrize(
        'filename, payload, should_flag',
        [
            # Existing test cases
            ('mock_filename', 'https://username:password@yelp.com', True),
            ('mock_filename', 'http://localhost:5000/<%= @variable %>', False),
            ('mock_filename', '"https://url:8000";@something else', False),
            ('mock_filename', '\'https://url:8000\';@something else', False),
            ('mock_filename', 'https://url:8000 @something else', False),
            ('mock_filename', 'https://url:8000/ @something else', False),
            ('mock_filename', 'https://username:password@example.com', False),

            # New test cases for Markdown files
            ('document.md', 'https://username:password@yelp.com', False),
            ('README.md', 'https://username:password@example.com', False),
        ],
    )
    def test_analyze_line(self, filename, payload, should_flag):
        logic = BasicAuthDetector()

        output = logic.analyze_line(filename=filename, line=payload)
        assert len(output) == int(should_flag)
