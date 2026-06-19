#!/usr/bin/env python3
"""
build-report.py - Render a markdown threat report from enriched IOC JSON.

Fills ioc-report-template.md's IOC table from vt-enricher.py output (or, if given
raw ioc-extractor output, lists indicators without detections).

Usage:
    python reports/build-report.py --enriched enriched-iocs.json \\
        --title "Emotet campaign" --tlp AMBER --output threat-report.md
"""
import argparse
import json
import os
import sys
from datetime import date

TEMPLATE = os.path.join(os.path.dirname(__file__), "ioc-report-template.md")


def rows_from_enriched(data):
    rows = []
    for rec in sorted(data.get("enriched", []),
                      key=lambda r: r.get("confidence", 0), reverse=True):
        if rec.get("status") != "found":
            continue
        note = (rec.get("as_owner") or rec.get("country")
                or (rec.get("names") or [""])[0] or rec.get("registrar") or "")
        rows.append("| {t} | {i} | {d} | {c} | {n} |".format(
            t=rec["type"], i=rec["indicator"], d=rec.get("detections", "-"),
            c=rec.get("confidence", "-"), n=note))
    return rows


def rows_from_raw(indicators):
    rows = []
    for key in ("sha256", "sha1", "md5", "domains", "ipv4", "urls"):
        for value in indicators.get(key, []):
            rows.append(f"| {key} | {value} | - | - | |")
    return rows


def main():
    parser = argparse.ArgumentParser(description="Build a markdown threat report.")
    parser.add_argument("--enriched", "-e", required=True, help="enriched-iocs.json or iocs.json")
    parser.add_argument("--title", "-t", default="Untitled investigation")
    parser.add_argument("--tlp", default="AMBER")
    parser.add_argument("--output", "-o", default="threat-report.md")
    args = parser.parse_args()

    with open(args.enriched, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    if "enriched" in data:
        rows = rows_from_enriched(data)
    else:
        rows = rows_from_raw(data.get("indicators", data))

    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        report = fh.read()

    table_header = ("| Type | Indicator | VT Detections | Confidence | Notes |\n"
                    "|------|-----------|---------------|------------|-------|")
    # Replace the template's placeholder IOC table block with real rows.
    start = report.find(table_header)
    if start != -1:
        end = report.find("\n\n", start)
        block = table_header + "\n" + ("\n".join(rows) if rows else "| - | _no indicators_ | - | - | |")
        report = report[:start] + block + report[end:]

    report = report.replace("{TITLE}", args.title)
    report = report.replace("{YYYY-MM-DD}", date.today().isoformat())
    report = report.replace("{WHITE | GREEN | AMBER | RED}", args.tlp)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Wrote report with {len(rows)} IOC rows -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
