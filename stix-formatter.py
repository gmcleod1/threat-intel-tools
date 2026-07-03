#!/usr/bin/env python3
"""
stix-formatter.py - Format extracted/enriched IOCs into a STIX 2.1 bundle.

Produces a STIX 2.1 Bundle of Indicator SDOs (with STIX patterning) from
ioc-extractor.py or vt-enricher.py output. Each indicator group is also
wrapped in a Grouping object so the bundle can be imported as a single
campaign/report unit by a TAXII 2.1 collection or MISP's STIX importer.

Usage:
    python stix-formatter.py --iocs iocs.json --name "Emotet campaign 2026-06" \\
        --tlp amber --output stix-bundle.json
"""
import argparse
import json
import re
import sys

from stix2 import Bundle, Grouping, Indicator
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

# STIX best practice requires the full hive name in windows-registry-key:key,
# not the short form (docs.oasis-open.org/cti/stix-bp/v1.0.0/cn01/).
HIVE_ABBREVIATIONS = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}
_HIVE_RE = re.compile(r"^(HKLM|HKCU|HKCR|HKU|HKCC)(?=\\|$)", re.IGNORECASE)


def normalize_hive(path: str) -> str:
    """Expand an abbreviated registry hive (HKCU\\...) to its full name."""
    match = _HIVE_RE.match(path)
    if not match:
        return path
    return HIVE_ABBREVIATIONS[match.group(1).upper()] + path[match.end():]


# (ioc-extractor key) -> STIX pattern builder
PATTERN_BUILDERS = {
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
    "domains": lambda v: f"[domain-name:value = '{v}']",
    "urls": lambda v: f"[url:value = '{_escape(v)}']",
    "emails": lambda v: f"[email-addr:value = '{v}']",
    "md5": lambda v: f"[file:hashes.'MD5' = '{v}']",
    "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "ssdeep": lambda v: f"[file:hashes.'SSDEEP' = '{v}']",
    "registry_paths": lambda v: f"[windows-registry-key:key = '{_escape(normalize_hive(v))}']",
}
INDICATOR_TYPES = {
    "ipv4": ["ipv4-addr"], "ipv6": ["ipv6-addr"], "domains": ["domain-name"],
    "urls": ["url"], "emails": ["email-addr"], "md5": ["file"], "sha1": ["file"],
    "sha256": ["file"], "ssdeep": ["file"], "registry_paths": ["windows-registry-key"],
}
TLP_MARKINGS = {
    "white": TLP_WHITE, "clear": TLP_WHITE, "green": TLP_GREEN,
    "amber": TLP_AMBER, "red": TLP_RED,
}


def _escape(value: str) -> str:
    """Escape backslash/quote for STIX pattern string literals."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _check_lists(indicators):
    """Reject non-list values so a bare string is never iterated char-by-char."""
    for key, values in indicators.items():
        if key in PATTERN_BUILDERS and not isinstance(values, (list, tuple)):
            raise ValueError(
                f"value for '{key}' must be a list, got {type(values).__name__}"
            )
    return indicators


def load_indicators(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "indicators" in data:
        return _check_lists(data["indicators"])
    if "enriched" in data:
        rebuilt = {k: [] for k in PATTERN_BUILDERS}
        bucket = {"file_hash": None, "ip": "ipv4", "domain": "domains", "url": "urls"}
        for rec in data["enriched"]:
            ind, kind = rec["indicator"], rec["type"]
            if kind == "file_hash":
                key = "sha256" if len(ind) == 64 else "sha1" if len(ind) == 40 else "md5"
            else:
                key = bucket.get(kind)
            if key:
                rebuilt[key].append(ind)
        return rebuilt
    return _check_lists(data)


def build_indicators(indicators, tlp_marking):
    objects = []
    for key, values in indicators.items():
        if key not in PATTERN_BUILDERS:
            continue
        for value in values:
            objects.append(Indicator(
                pattern=PATTERN_BUILDERS[key](value),
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                object_marking_refs=[tlp_marking] if tlp_marking else [],
                labels=[key],
            ))
    return objects


def build_bundle(indicators, name, description, tlp):
    marking = TLP_MARKINGS.get(tlp)
    indicator_objs = build_indicators(indicators, marking)
    if not indicator_objs:
        # Grouping requires a non-empty object_refs, so bail out with a clear
        # message instead of letting stix2 raise MissingPropertiesError.
        raise ValueError("no indicators found in input; nothing to export")

    grouping = Grouping(
        name=name,
        description=description or "",
        context="suspicious-activity",
        object_refs=[i.id for i in indicator_objs],
        object_marking_refs=[marking] if marking else [],
    )

    bundle_objects = [grouping, *indicator_objs]
    if marking is not None:
        bundle_objects.insert(0, marking)

    return Bundle(objects=bundle_objects)


def main():
    parser = argparse.ArgumentParser(description="Format IOCs as a STIX 2.1 bundle.")
    parser.add_argument("--iocs", "-i", required=True)
    parser.add_argument("--name", required=True, help="Grouping/report name")
    parser.add_argument("--description", default="", help="Grouping description")
    parser.add_argument("--tlp", default="amber", choices=list(TLP_MARKINGS))
    parser.add_argument("--output", "-o", default="stix-bundle.json")
    args = parser.parse_args()

    try:
        indicators = load_indicators(args.iocs)
        bundle = build_bundle(indicators, args.name, args.description, args.tlp)
    except ValueError as exc:
        sys.exit(f"error: {exc}")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(bundle.serialize(pretty=True))

    n = sum(1 for o in bundle.objects if o["type"] == "indicator")
    print(f"Wrote STIX 2.1 bundle with {n} indicators ({args.tlp.upper()}) -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
