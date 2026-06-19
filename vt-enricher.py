#!/usr/bin/env python3
"""
vt-enricher.py - Batch-enrich extracted IOCs via the VirusTotal API (v3).

Reads the JSON produced by ioc-extractor.py, looks up file hashes, IPs, domains,
and URLs against VirusTotal, and writes an enriched report with detection ratios
and a simple confidence score. Respects the VT public-API rate limit
(4 requests/minute) by default.

Usage:
    python vt-enricher.py --iocs iocs.json --output enriched-iocs.json
    python vt-enricher.py --iocs iocs.json --api-key-file config/vt-api-key.txt

The API key is read (in order) from --api-key, $VT_API_KEY, or the key file.
NEVER commit your real key — config/vt-api-key.txt is git-ignored.
"""
import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install -r requirements.txt")

VT_BASE = "https://www.virustotal.com/api/v3"
PUBLIC_RATE_DELAY = 15  # seconds between calls (4/min public API)


def load_api_key(cli_key, key_file):
    if cli_key:
        return cli_key.strip()
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"].strip()
    if key_file and os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    sys.exit(
        "No VirusTotal API key found. Use --api-key, set $VT_API_KEY, or create "
        "config/vt-api-key.txt (copy from config/vt-api-key.example.txt)."
    )


def vt_get(session, path):
    resp = session.get(f"{VT_BASE}/{path}", timeout=30)
    if resp.status_code == 404:
        return {"_status": "not_found"}
    if resp.status_code == 401:
        sys.exit("VirusTotal returned 401 Unauthorized - check your API key.")
    if resp.status_code == 429:
        return {"_status": "rate_limited"}
    resp.raise_for_status()
    return resp.json()


def summarize_stats(stats):
    """Turn VT last_analysis_stats into a (malicious, total, score) tuple."""
    if not stats:
        return 0, 0, 0.0
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    return malicious, total, round(malicious / total, 3)


def enrich_hash(session, h):
    data = vt_get(session, f"files/{h}")
    if "_status" in data:
        return {"indicator": h, "type": "file_hash", "status": data["_status"]}
    attr = data.get("data", {}).get("attributes", {})
    mal, total, score = summarize_stats(attr.get("last_analysis_stats"))
    return {
        "indicator": h,
        "type": "file_hash",
        "status": "found",
        "detections": f"{mal}/{total}",
        "confidence": score,
        "names": attr.get("names", [])[:5],
        "type_description": attr.get("type_description"),
        "first_submission": attr.get("first_submission_date"),
        "last_submission": attr.get("last_submission_date"),
    }


def enrich_ip(session, ip):
    data = vt_get(session, f"ip_addresses/{ip}")
    if "_status" in data:
        return {"indicator": ip, "type": "ip", "status": data["_status"]}
    attr = data.get("data", {}).get("attributes", {})
    mal, total, score = summarize_stats(attr.get("last_analysis_stats"))
    return {
        "indicator": ip,
        "type": "ip",
        "status": "found",
        "detections": f"{mal}/{total}",
        "confidence": score,
        "asn": attr.get("asn"),
        "as_owner": attr.get("as_owner"),
        "country": attr.get("country"),
    }


def enrich_domain(session, domain):
    data = vt_get(session, f"domains/{domain}")
    if "_status" in data:
        return {"indicator": domain, "type": "domain", "status": data["_status"]}
    attr = data.get("data", {}).get("attributes", {})
    mal, total, score = summarize_stats(attr.get("last_analysis_stats"))
    return {
        "indicator": domain,
        "type": "domain",
        "status": "found",
        "detections": f"{mal}/{total}",
        "confidence": score,
        "registrar": attr.get("registrar"),
        "creation_date": attr.get("creation_date"),
    }


def enrich_url(session, url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = vt_get(session, f"urls/{url_id}")
    if "_status" in data:
        return {"indicator": url, "type": "url", "status": data["_status"]}
    attr = data.get("data", {}).get("attributes", {})
    mal, total, score = summarize_stats(attr.get("last_analysis_stats"))
    return {
        "indicator": url,
        "type": "url",
        "status": "found",
        "detections": f"{mal}/{total}",
        "confidence": score,
        "final_url": attr.get("last_final_url"),
    }


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs via VirusTotal.")
    parser.add_argument("--iocs", "-i", required=True, help="iocs.json from ioc-extractor")
    parser.add_argument("--output", "-o", default="enriched-iocs.json")
    parser.add_argument("--api-key", help="VT API key (overrides env/file)")
    parser.add_argument("--api-key-file", default="config/vt-api-key.txt")
    parser.add_argument("--delay", type=float, default=PUBLIC_RATE_DELAY,
                        help="Seconds between calls (default 15 for public API)")
    args = parser.parse_args()

    api_key = load_api_key(args.api_key, args.api_key_file)
    with open(args.iocs, "r", encoding="utf-8") as fh:
        iocs = json.load(fh)
    ind = iocs.get("indicators", iocs)

    session = requests.Session()
    session.headers.update({"x-apikey": api_key, "accept": "application/json"})

    jobs = []
    for h in ind.get("sha256", []) + ind.get("sha1", []) + ind.get("md5", []):
        jobs.append(("hash", h))
    for ip in ind.get("ipv4", []):
        jobs.append(("ip", ip))
    for d in ind.get("domains", []):
        jobs.append(("domain", d))
    for u in ind.get("urls", []):
        jobs.append(("url", u))

    enriched = []
    for n, (kind, value) in enumerate(jobs, 1):
        print(f"[{n}/{len(jobs)}] {kind}: {value}", file=sys.stderr)
        if kind == "hash":
            enriched.append(enrich_hash(session, value))
        elif kind == "ip":
            enriched.append(enrich_ip(session, value))
        elif kind == "domain":
            enriched.append(enrich_domain(session, value))
        elif kind == "url":
            enriched.append(enrich_url(session, value))
        if n < len(jobs):
            time.sleep(args.delay)

    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": args.iocs,
        "enriched": enriched,
    }
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    flagged = [e for e in enriched if e.get("confidence", 0) > 0]
    print(f"Enriched {len(enriched)} indicators ({len(flagged)} flagged) -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
