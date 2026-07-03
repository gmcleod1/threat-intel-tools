"""Regression tests for misp-formatter.py (MISP event JSON output)."""
import json

import pytest


def test_event_structure_and_type_mapping(misp_formatter, sample_indicators):
    event = misp_formatter.build_event(sample_indicators, "test event", "amber", 1, 2)["Event"]
    assert event["info"] == "test event"
    assert event["threat_level_id"] == "2"
    assert event["analysis"] == "1"
    assert event["published"] is False
    assert event["Tag"] == [{"name": "tlp:amber"}]

    by_type = {a["type"]: a for a in event["Attribute"]}
    assert len(event["Attribute"]) == 10
    assert by_type["ip-dst"]["category"] == "Network activity"
    assert by_type["domain"]["category"] == "Network activity"
    assert by_type["email-src"]["category"] == "Payload delivery"
    assert by_type["sha256"]["category"] == "Payload delivery"
    assert by_type["regkey"]["category"] == "Persistence mechanism"


def test_to_ids_flags(misp_formatter, sample_indicators):
    attributes = misp_formatter.build_event(
        sample_indicators, "t", "amber", 1, 2)["Event"]["Attribute"]
    for attr in attributes:
        if attr["type"] == "regkey":
            assert attr["to_ids"] is False
        else:
            assert attr["to_ids"] is True


def test_empty_input_produces_empty_event(misp_formatter, empty_indicators):
    event = misp_formatter.build_event(empty_indicators, "t", "amber", 1, 2)["Event"]
    assert event["Attribute"] == []


def test_flat_dict_with_string_value_rejected(misp_formatter, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"ipv4": "198.51.100.23"}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        misp_formatter.load_indicators(str(bad))


def test_flat_dict_with_lists_accepted(misp_formatter, tmp_path):
    flat = tmp_path / "flat.json"
    flat.write_text(json.dumps({"ipv4": ["198.51.100.23"]}), encoding="utf-8")
    ind = misp_formatter.load_indicators(str(flat))
    assert ind["ipv4"] == ["198.51.100.23"]


def test_tlp_tags(misp_formatter, sample_indicators):
    for tlp in ("white", "clear", "green", "amber", "amber+strict", "red"):
        event = misp_formatter.build_event(sample_indicators, "t", tlp, 1, 2)["Event"]
        assert event["Tag"] == [{"name": f"tlp:{tlp}"}]


def test_load_enriched_input(misp_formatter, enriched_doc, tmp_path):
    path = tmp_path / "enriched.json"
    path.write_text(json.dumps(enriched_doc), encoding="utf-8")
    ind = misp_formatter.load_indicators(str(path))
    assert ind["sha256"] == [
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
    assert ind["sha1"] == ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]
    assert ind["md5"] == ["5d41402abc4b2a76b9719d911017c592"]
    assert ind["ipv4"] == ["198.51.100.23"]
    assert ind["domains"] == ["c2-node1.example"]
    assert ind["urls"] == ["http://malicious-update.example/install.php"]
