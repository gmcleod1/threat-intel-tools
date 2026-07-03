"""Regression tests for stix-formatter.py (STIX 2.1 bundle output)."""
import json

import pytest
from stix2patterns.validator import run_validator


def _indicators(bundle):
    return [o for o in bundle.objects if o["type"] == "indicator"]


def test_bundle_structure(stix_formatter, sample_indicators):
    bundle = stix_formatter.build_bundle(sample_indicators, "test", "desc", "amber")
    indicators = _indicators(bundle)
    groupings = [o for o in bundle.objects if o["type"] == "grouping"]
    markings = [o for o in bundle.objects if o["type"] == "marking-definition"]

    assert len(indicators) == 10  # one per populated IOC type
    assert len(groupings) == 1
    assert len(markings) == 1
    assert markings[0]["name"] == "TLP:AMBER"
    # every indicator is referenced by the grouping and carries the marking
    assert sorted(groupings[0]["object_refs"]) == sorted(i["id"] for i in indicators)
    assert all(i["object_marking_refs"] == [markings[0]["id"]] for i in indicators)


def test_all_patterns_are_valid_stix21(stix_formatter, sample_indicators):
    bundle = stix_formatter.build_bundle(sample_indicators, "test", "", "amber")
    for indicator in _indicators(bundle):
        errors = run_validator(indicator["pattern"], stix_version="2.1")
        assert not errors, f"invalid pattern {indicator['pattern']}: {errors}"


def test_empty_input_raises_clean_error(stix_formatter, empty_indicators):
    with pytest.raises(ValueError, match="no indicators"):
        stix_formatter.build_bundle(empty_indicators, "test", "", "amber")


def test_flat_dict_with_string_value_rejected(stix_formatter, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"ipv4": "198.51.100.23"}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        stix_formatter.load_indicators(str(bad))


@pytest.mark.parametrize("raw,expected", [
    ("HKCU\\Software\\Run\\Updater", "HKEY_CURRENT_USER\\Software\\Run\\Updater"),
    ("hklm\\SYSTEM\\Foo", "HKEY_LOCAL_MACHINE\\SYSTEM\\Foo"),
    ("HKCR\\CLSID", "HKEY_CLASSES_ROOT\\CLSID"),
    ("HKU\\S-1-5-18", "HKEY_USERS\\S-1-5-18"),
    ("HKCC\\System", "HKEY_CURRENT_CONFIG\\System"),
    ("HKEY_USERS\\S-1-5-18", "HKEY_USERS\\S-1-5-18"),  # already full: unchanged
    ("HKUnrelated\\x", "HKUnrelated\\x"),              # not a hive prefix: unchanged
])
def test_normalize_hive(stix_formatter, raw, expected):
    assert stix_formatter.normalize_hive(raw) == expected


def test_registry_pattern_uses_full_hive_and_validates(stix_formatter, empty_indicators):
    indicators = dict(empty_indicators,
                      registry_paths=["HKLM\\SOFTWARE\\Evil\\Persist"])
    bundle = stix_formatter.build_bundle(indicators, "test", "", "amber")
    pattern = _indicators(bundle)[0]["pattern"]
    assert "HKEY_LOCAL_MACHINE" in pattern
    assert "HKLM" not in pattern
    assert not run_validator(pattern, stix_version="2.1")


def test_pattern_escaping(stix_formatter):
    assert stix_formatter._escape("a'b\\c") == "a\\'b\\\\c"


def test_tlp_variants(stix_formatter, empty_indicators):
    indicators = dict(empty_indicators, ipv4=["198.51.100.23"])
    for tlp, expected in (("white", "TLP:WHITE"), ("clear", "TLP:WHITE"),
                          ("green", "TLP:GREEN"), ("red", "TLP:RED")):
        bundle = stix_formatter.build_bundle(indicators, "t", "", tlp)
        markings = [o for o in bundle.objects if o["type"] == "marking-definition"]
        assert markings[0]["name"] == expected


def test_load_enriched_input(stix_formatter, enriched_doc, tmp_path):
    path = tmp_path / "enriched.json"
    path.write_text(json.dumps(enriched_doc), encoding="utf-8")
    ind = stix_formatter.load_indicators(str(path))
    assert ind["sha256"] == [
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
    assert ind["sha1"] == ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]
    assert ind["md5"] == ["5d41402abc4b2a76b9719d911017c592"]
    assert ind["ipv4"] == ["198.51.100.23"]
    assert ind["domains"] == ["c2-node1.example"]
    assert ind["urls"] == ["http://malicious-update.example/install.php"]


def test_bundle_serializes_to_json(stix_formatter, sample_indicators):
    bundle = stix_formatter.build_bundle(sample_indicators, "test", "", "amber")
    parsed = json.loads(bundle.serialize())
    assert parsed["type"] == "bundle"
    assert all(o["spec_version"] == "2.1" for o in parsed["objects"]
               if o["type"] != "bundle")
