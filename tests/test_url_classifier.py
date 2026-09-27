import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from classify_urls import has_params, is_js_file, sensitive_extension, classify  # noqa: E402


class TestHasParams:
    def test_url_with_query_string(self):
        assert has_params("https://example.com/search?q=test")

    def test_url_with_multiple_params(self):
        assert has_params("https://example.com/api?id=1&sort=desc")

    def test_url_without_query_string(self):
        assert not has_params("https://example.com/about")

    def test_bare_question_mark_no_value(self):
        # urlsplit treats a trailing "?" with nothing after it as an empty query
        assert not has_params("https://example.com/page?")


class TestIsJsFile:
    def test_plain_js_file(self):
        assert is_js_file("https://example.com/static/app.js")

    def test_js_file_with_query_string(self):
        assert is_js_file("https://example.com/static/app.js?v=123")

    def test_non_js_file(self):
        assert not is_js_file("https://example.com/static/app.css")

    def test_path_containing_js_but_not_extension(self):
        assert not is_js_file("https://example.com/js/index.html")


class TestSensitiveExtension:
    def test_env_file_flagged(self):
        assert sensitive_extension("https://example.com/.env") == "env"

    def test_sql_backup_flagged(self):
        assert sensitive_extension("https://example.com/backup.sql") == "sql"

    def test_safe_extension_not_flagged(self):
        assert sensitive_extension("https://example.com/index.html") is None

    def test_no_extension_not_flagged(self):
        assert sensitive_extension("https://example.com/api/users") is None

    def test_query_string_does_not_hide_extension_match(self):
        # extension check is on the path, not the full URL, so a query string
        # after a safe-looking path shouldn't create false positives or negatives
        assert sensitive_extension("https://example.com/page.html?next=x.sql") is None


class TestClassify:
    def test_classifies_a_mixed_list(self):
        urls = [
            "https://example.com/search?q=1",
            "https://example.com/static/app.js",
            "https://example.com/.env",
            "https://example.com/about",
        ]
        params, js_files, sensitive = classify(urls)
        assert params == ["https://example.com/search?q=1"]
        assert js_files == ["https://example.com/static/app.js"]
        assert sensitive == ["https://example.com/.env"]

    def test_a_url_can_land_in_multiple_buckets(self):
        urls = ["https://example.com/app.js?debug=env"]
        params, js_files, sensitive = classify(urls)
        assert params == urls
        assert js_files == urls
        assert sensitive == []  # extension check is on the .js path, not the query

    def test_empty_list(self):
        assert classify([]) == ([], [], [])
