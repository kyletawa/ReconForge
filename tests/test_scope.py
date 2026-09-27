import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scope import Scope, ScopeError  # noqa: E402


def make_scope(allowed, excluded=None):
    return Scope(target="example.com", allowed=allowed, excluded=excluded or [])


class TestWildcardMatching:
    def test_exact_apex_allowed(self):
        scope = make_scope(["example.com"])
        assert scope.is_allowed("example.com")

    def test_apex_pattern_does_not_match_subdomain(self):
        scope = make_scope(["example.com"])
        assert not scope.is_allowed("www.example.com")

    def test_wildcard_matches_subdomain(self):
        scope = make_scope(["*.example.com"])
        assert scope.is_allowed("www.example.com")
        assert scope.is_allowed("api.example.com")

    def test_wildcard_does_not_match_apex(self):
        scope = make_scope(["*.example.com"])
        assert not scope.is_allowed("example.com")

    def test_wildcard_does_not_match_unrelated_domain(self):
        scope = make_scope(["*.example.com"])
        assert not scope.is_allowed("example.org")
        assert not scope.is_allowed("evilexample.com")

    def test_case_insensitive(self):
        scope = make_scope(["*.example.com"])
        assert scope.is_allowed("WWW.EXAMPLE.COM")

    def test_trailing_dot_normalized(self):
        scope = make_scope(["*.example.com"])
        assert scope.is_allowed("www.example.com.")


class TestExclusionPrecedence:
    def test_excluded_overrides_wildcard_allow(self):
        scope = make_scope(["*.example.com"], excluded=["admin.example.com"])
        assert scope.is_allowed("www.example.com")
        assert not scope.is_allowed("admin.example.com")

    def test_excluded_wildcard_blocks_a_whole_subtree(self):
        scope = make_scope(["*.example.com"], excluded=["*.internal.example.com"])
        assert scope.is_allowed("api.example.com")
        assert not scope.is_allowed("db.internal.example.com")


class TestDefaultDeny:
    def test_host_not_matching_anything_is_denied(self):
        scope = make_scope(["example.com"])
        assert not scope.is_allowed("random-host.net")

    def test_empty_host_is_denied(self):
        scope = make_scope(["*.example.com"])
        assert not scope.is_allowed("")
        assert not scope.is_allowed(None)


class TestFilterHosts:
    def test_splits_into_allowed_and_rejected(self):
        scope = make_scope(["*.example.com", "example.com"], excluded=["admin.example.com"])
        hosts = ["example.com", "www.example.com", "admin.example.com", "evil.net"]
        allowed, rejected = scope.filter_hosts(hosts)
        assert allowed == ["example.com", "www.example.com"]
        assert rejected == ["admin.example.com", "evil.net"]


class TestFromFile:
    def test_loads_valid_scope_file(self, tmp_path):
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text(
            "target: example.com\n"
            "scope:\n"
            "  allowed:\n"
            "    - example.com\n"
            "    - '*.example.com'\n"
            "  excluded:\n"
            "    - admin.example.com\n"
        )
        scope = Scope.from_file(scope_file)
        assert scope.target == "example.com"
        assert scope.is_allowed("www.example.com")
        assert not scope.is_allowed("admin.example.com")

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ScopeError):
            Scope.from_file(tmp_path / "does_not_exist.yaml")

    def test_missing_target_raises(self, tmp_path):
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("scope:\n  allowed:\n    - example.com\n")
        with pytest.raises(ScopeError):
            Scope.from_file(scope_file)

    def test_missing_allowed_raises(self, tmp_path):
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("target: example.com\nscope:\n  allowed: []\n")
        with pytest.raises(ScopeError):
            Scope.from_file(scope_file)

    def test_invalid_yaml_raises(self, tmp_path):
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text("target: [this is not: valid: yaml")
        with pytest.raises(ScopeError):
            Scope.from_file(scope_file)
