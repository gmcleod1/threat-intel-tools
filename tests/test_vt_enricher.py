"""Tests for vt-enricher.py helpers that run without network access."""
import pytest


def test_summarize_stats_normal(vt_enricher):
    mal, total, score = vt_enricher.summarize_stats(
        {"malicious": 40, "suspicious": 10, "harmless": 50, "undetected": 0})
    assert (mal, total, score) == (50, 100, 0.5)


def test_summarize_stats_empty(vt_enricher):
    assert vt_enricher.summarize_stats({}) == (0, 0, 0.0)
    assert vt_enricher.summarize_stats(None) == (0, 0, 0.0)


def test_summarize_stats_never_divides_by_zero(vt_enricher):
    mal, total, score = vt_enricher.summarize_stats(
        {"malicious": 0, "harmless": 0})
    assert score == 0.0


def test_load_api_key_precedence(vt_enricher, monkeypatch, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text("# comment line\nfile-key\n", encoding="utf-8")

    # CLI key wins over everything
    monkeypatch.setenv("VT_API_KEY", "env-key")
    assert vt_enricher.load_api_key(" cli-key ", str(key_file)) == "cli-key"
    # then the environment variable
    assert vt_enricher.load_api_key(None, str(key_file)) == "env-key"
    # then the key file, skipping comments
    monkeypatch.delenv("VT_API_KEY")
    assert vt_enricher.load_api_key(None, str(key_file)) == "file-key"


def test_load_api_key_missing_exits(vt_enricher, monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        vt_enricher.load_api_key(None, str(tmp_path / "does-not-exist.txt"))
