"""End-to-end CLI tests: extractor output feeds both formatters via subprocess."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample-report.txt"


def run_tool(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / script), *args],
        capture_output=True, text=True, cwd=ROOT,
    )


def test_extract_then_stix(tmp_path):
    iocs = tmp_path / "iocs.json"
    bundle_path = tmp_path / "bundle.json"

    result = run_tool("ioc-extractor.py", "--file", str(SAMPLE), "--output", str(iocs))
    assert result.returncode == 0, result.stderr

    result = run_tool("stix-formatter.py", "--iocs", str(iocs),
                      "--name", "pipeline test", "--output", str(bundle_path))
    assert result.returncode == 0, result.stderr

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    groupings = [o for o in bundle["objects"] if o["type"] == "grouping"]
    assert len(indicators) >= 10
    assert len(groupings) == 1
    assert sorted(groupings[0]["object_refs"]) == sorted(i["id"] for i in indicators)


def test_extract_then_misp(tmp_path):
    iocs = tmp_path / "iocs.json"
    event_path = tmp_path / "event.json"

    result = run_tool("ioc-extractor.py", "--file", str(SAMPLE), "--output", str(iocs))
    assert result.returncode == 0, result.stderr

    result = run_tool("misp-formatter.py", "--iocs", str(iocs),
                      "--info", "pipeline test", "--output", str(event_path))
    assert result.returncode == 0, result.stderr

    event = json.loads(event_path.read_text(encoding="utf-8"))["Event"]
    assert len(event["Attribute"]) >= 10
    assert event["info"] == "pipeline test"


def test_stix_empty_input_exits_cleanly(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"indicators": {"ipv4": []}}), encoding="utf-8")

    result = run_tool("stix-formatter.py", "--iocs", str(empty), "--name", "empty",
                      "--output", str(tmp_path / "out.json"))
    assert result.returncode == 1
    assert "no indicators" in result.stderr
    assert "Traceback" not in result.stderr


def test_stix_malformed_input_exits_cleanly(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"ipv4": "198.51.100.23"}), encoding="utf-8")

    result = run_tool("stix-formatter.py", "--iocs", str(bad), "--name", "bad",
                      "--output", str(tmp_path / "out.json"))
    assert result.returncode == 1
    assert "must be a list" in result.stderr
    assert "Traceback" not in result.stderr
