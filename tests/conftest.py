"""Shared fixtures: load the hyphen-named tool scripts as importable modules."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def ioc_extractor():
    return _load("ioc_extractor", "ioc-extractor.py")


@pytest.fixture(scope="session")
def misp_formatter():
    return _load("misp_formatter", "misp-formatter.py")


@pytest.fixture(scope="session")
def stix_formatter():
    return _load("stix_formatter", "stix-formatter.py")


@pytest.fixture(scope="session")
def vt_enricher():
    return _load("vt_enricher", "vt-enricher.py")


@pytest.fixture(scope="session")
def sample_report_text():
    path = ROOT / "examples" / "sample-report.txt"
    return path.read_text(encoding="utf-8")


@pytest.fixture()
def sample_indicators():
    """A small typed-indicator dict in ioc-extractor output shape."""
    empty = {
        "ipv4": [], "ipv6": [], "domains": [], "urls": [], "emails": [],
        "md5": [], "sha1": [], "sha256": [], "ssdeep": [], "registry_paths": [],
    }
    return dict(
        empty,
        ipv4=["198.51.100.23"],
        ipv6=["2001:db8::1"],
        domains=["evil.example"],
        urls=["http://evil.example/a.php?q=1"],
        emails=["a@evil.example"],
        md5=["5d41402abc4b2a76b9719d911017c592"],
        sha1=["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
        sha256=["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
        ssdeep=["3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"],
        registry_paths=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
    )


@pytest.fixture()
def empty_indicators():
    return {
        "ipv4": [], "ipv6": [], "domains": [], "urls": [], "emails": [],
        "md5": [], "sha1": [], "sha256": [], "ssdeep": [], "registry_paths": [],
    }


@pytest.fixture()
def enriched_doc():
    """Mimics vt-enricher.py output, including a not_found record."""
    return {
        "generated": "2026-07-03T00:00:00+00:00",
        "source": "iocs.json",
        "enriched": [
            {"indicator": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
             "type": "file_hash", "status": "found"},
            {"indicator": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
             "type": "file_hash", "status": "found"},
            {"indicator": "5d41402abc4b2a76b9719d911017c592",
             "type": "file_hash", "status": "not_found"},
            {"indicator": "198.51.100.23", "type": "ip", "status": "found"},
            {"indicator": "c2-node1.example", "type": "domain", "status": "found"},
            {"indicator": "http://malicious-update.example/install.php",
             "type": "url", "status": "found"},
        ],
    }
