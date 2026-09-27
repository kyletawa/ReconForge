import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config_validator import parse_conf  # noqa: E402


class TestValidConfig:
    def test_known_keys_parse_cleanly(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("THREADS=100\nRATE_LIMIT=200\nTOP_PORTS=2000\n")
        values, errors = parse_conf(conf)
        assert errors == []
        assert values == {"THREADS": "100", "RATE_LIMIT": "200", "TOP_PORTS": "2000"}

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("# a comment\n\nTHREADS=50\n\n# another\n")
        values, errors = parse_conf(conf)
        assert errors == []
        assert values == {"THREADS": "50"}

    def test_quoted_string_value_unquoted(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text('RESOLVERS="/opt/resolvers.txt"\n')
        values, errors = parse_conf(conf)
        assert errors == []
        assert values["RESOLVERS"] == "/opt/resolvers.txt"

    def test_negative_int_allowed_by_pattern(self, tmp_path):
        # not semantically valid for THREADS, but the type check only enforces
        # "is an integer" — range validation is out of scope for this checker
        conf = tmp_path / "recon.conf"
        conf.write_text("THREADS=-1\n")
        values, errors = parse_conf(conf)
        assert errors == []
        assert values["THREADS"] == "-1"


class TestInvalidConfig:
    def test_unknown_key_flagged(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("THREAD=100\n")  # typo: missing S
        values, errors = parse_conf(conf)
        assert len(errors) == 1
        assert "unknown config key" in errors[0]
        assert "THREAD" in errors[0]

    def test_non_integer_value_for_int_key_flagged(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("THREADS=fast\n")
        values, errors = parse_conf(conf)
        assert len(errors) == 1
        assert "must be an integer" in errors[0]

    def test_malformed_line_flagged(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("THREADS 100\n")  # missing '='
        values, errors = parse_conf(conf)
        assert len(errors) == 1
        assert "not a valid KEY=VALUE line" in errors[0]

    def test_missing_file_flagged(self, tmp_path):
        values, errors = parse_conf(tmp_path / "nope.conf")
        assert values == {}
        assert len(errors) == 1
        assert "not found" in errors[0]

    def test_multiple_errors_all_reported(self, tmp_path):
        conf = tmp_path / "recon.conf"
        conf.write_text("THREAD=100\nRATE_LIMIT=fast\n")
        values, errors = parse_conf(conf)
        assert len(errors) == 2
