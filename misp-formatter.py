#!/usr/bin/env python3
"""
misp-formatter.py - Format extracted/enriched IOCs into a MISP event JSON.

Produces a MISP-compatible event document (the structure accepted by the MISP
"Add Event" / REST import) from ioc-extractor.py or vt-enricher.py output.
Maps each indicator to the correct MISP attribute type and category, and applies
a TLP tag.

Usage:
    python misp-formatter.py --iocs iocs.json --info "Emotet campaign 2026-06" \\
        --tlp amber --output misp-event.json
"""
import argparse
import json
import sys
from datetime import datetime, timezone

# (ioc-extractor key) -> (MISP attribute type, MISP category)
TYPE_MAP = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "domains": ("domain", "Network activity"),
    "urls": ("url", "Network activity"),
    "emails": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "ssdeep": ("ssdeep", "Payload delivery"),
    "registry_paths": ("regkey", "Persistence mechanism"),
}
TLP_TAGS = {"white": "tlp:white", "clear": "tlp:clear", "green": "tlp:green",
            "amber": "tlp:amber", "amber+strict": "tlp:amber+strict", "red": "tlp:red"}


def _check_lists(indicators):
    """Reject non-list values so a bare string is never iterated char-by-char."""
    for key, values in indicators.items():
        if key in TYPE_MAP and not isinstance(values, (list, tuple)):
            raise ValueError(
                f"value for '{key}' must be a list, got {type(values).__name__}"
            )
    return indicators


def load_indicators(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Accept either ioc-extractor output (has "indicators") or a flat dict.
    if "indicators" in data:
        return _check_lists(data["indicators"])
    if "enriched" in data:
        # Rebuild a typed dict from enriched records.
        rebuilt = {k: [] for k in TYPE_MAP}
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


def build_event(indicators, info, tlp, analysis, threat_level):
    now = datetime.now(timezone.utc)
    attributes = []
    for key, values in indicators.items():
        if key not in TYPE_MAP:
            continue
        mtype, category = TYPE_MAP[key]
        for value in values:
            attributes.append({
                "type": mtype,
                "category": category,
                "value": value,
                "to_ids": mtype not in ("regkey",),
                "comment": "",
            })

    return {
        "Event": {
            "info": info,
            "date": now.strftime("%Y-%m-%d"),
            "threat_level_id": str(threat_level),   # 1 high, 2 medium, 3 low, 4 undef
            "analysis": str(analysis),              # 0 initial, 1 ongoing, 2 complete
            "distribution": "0",                    # your org only by default
            "published": False,
            "Tag": [{"name": TLP_TAGS.get(tlp, "tlp:amber")}],
            "Attribute": attributes,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Format IOCs as a MISP event.")
    parser.add_argument("--iocs", "-i", required=True)
    parser.add_argument("--info", required=True, help="Event title/description")
    parser.add_argument("--tlp", default="amber", choices=list(TLP_TAGS))
    parser.add_argument("--analysis", type=int, default=1, choices=[0, 1, 2])
    parser.add_argument("--threat-level", type=int, default=2, choices=[1, 2, 3, 4])
    parser.add_argument("--output", "-o", default="misp-event.json")
    args = parser.parse_args()

    try:
        indicators = load_indicators(args.iocs)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    event = build_event(indicators, args.info, args.tlp, args.analysis, args.threat_level)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(event, fh, indent=2)
    n = len(event["Event"]["Attribute"])
    print(f"Wrote MISP event with {n} attributes ({args.tlp.upper()}) -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
