#!/usr/bin/env python3
"""
ioc-extractor.py - Extract structured indicators of compromise from unstructured text.

Parses reports, logs, or analysis notes and pulls out IPs, domains, hashes, URLs,
emails, and Windows registry paths. Handles common "defanged" formats
(hxxp://, 1[.]2[.]3[.]4, evil[dot]com) and filters private/reserved IPs.

Usage:
    python ioc-extractor.py --file report.txt --output iocs.json
    python ioc-extractor.py --file report.txt            # prints JSON to stdout
    cat report.txt | python ioc-extractor.py             # reads stdin
"""
import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone

# Domains/hosts that are almost always benign noise in reports. Extend as needed.
DEFAULT_DOMAIN_DENYLIST = {
    "microsoft.com", "windows.com", "google.com", "github.com", "virustotal.com",
    "mitre.org", "wikipedia.org", "example.com", "schema.org", "w3.org",
}

# Interior segments may contain spaces (e.g. \Windows NT\), but the final
# segment may not — otherwise the greedy match swallows prose that follows
# the path on the same line ("...\Run\Updater from billing").
REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
    r"(?:\\[\w\-. ]+)*\\[\w\-.]+",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
HASH_RES = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
SSDEEP_RE = re.compile(r"\b\d{1,5}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b")


def refang(text: str) -> str:
    """Convert common defanged indicators back to their live form for parsing."""
    replacements = {
        "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".", "(dot)": ".",
        "[:]": ":", "[://]": "://", "hxxp": "http", "hXXp": "http",
        "[@]": "@", "[at]": "@",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


# Explicit private/internal/non-routable ranges. Done by membership rather than
# is_global/is_private so behavior is identical across Python versions (those
# properties disagree on RFC-5737 documentation ranges between 3.x releases).
_EXCLUDED_V4_NETS = [
    ipaddress.ip_network(c) for c in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
        "127.0.0.0/8",          # loopback
        "169.254.0.0/16",       # link-local
        "100.64.0.0/10",        # CGNAT
        "0.0.0.0/8",            # this-network
        "224.0.0.0/4",          # multicast
        "240.0.0.0/4",          # reserved/broadcast
    )
]


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return not any(ip in net for net in _EXCLUDED_V4_NETS)


def is_valid_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def extract(text: str, domain_denylist=None) -> dict:
    domain_denylist = domain_denylist or DEFAULT_DOMAIN_DENYLIST
    refanged = refang(text)

    urls = sorted(set(URL_RE.findall(refanged)))
    emails = sorted(set(EMAIL_RE.findall(refanged)))

    # Domains that appear inside URLs/emails are still reported, but we drop
    # the username portion of emails and the path portion of URLs first.
    hosts_in_context = set()
    for u in urls:
        m = re.search(r"://([^/:\s]+)", u)
        if m:
            hosts_in_context.add(m.group(1).lower())
    for e in emails:
        hosts_in_context.add(e.split("@", 1)[1].lower())

    domains = set()
    for d in DOMAIN_RE.findall(refanged):
        d_low = d.lower().rstrip(".")
        if d_low in domain_denylist:
            continue
        # Skip things that are actually filenames (e.g. report.txt, payload.exe)
        if re.search(r"\.(exe|dll|txt|md|json|csv|log|png|jpg|jpeg|gif|pdf|zip|doc|"
                     r"docx|xls|xlsx|php|asp|aspx|jsp|html|htm|js|py|ps1|bat|dat)$", d_low):
            continue
        domains.add(d_low)
    domains |= hosts_in_context
    domains = sorted(domains - domain_denylist)

    ipv4 = sorted({ip for ip in IPV4_RE.findall(refanged) if is_public_ipv4(ip)})
    ipv6 = sorted({ip for ip in IPV6_RE.findall(refanged) if is_valid_ipv6(ip)})

    # Hashes: assign each token to its longest matching type so a SHA256 is not
    # also reported as overlapping MD5/SHA1 fragments.
    sha256 = set(HASH_RES["sha256"].findall(refanged))
    sha1 = set(HASH_RES["sha1"].findall(refanged))
    md5 = set(HASH_RES["md5"].findall(refanged))

    registry = sorted({r.rstrip(". ") for r in REGISTRY_RE.findall(refanged)})
    ssdeep = sorted(set(SSDEEP_RE.findall(refanged)))

    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "indicators": {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "domains": domains,
            "urls": urls,
            "emails": emails,
            "md5": sorted(md5),
            "sha1": sorted(sha1),
            "sha256": sorted(sha256),
            "ssdeep": ssdeep,
            "registry_paths": registry,
        },
        "counts": {
            "ipv4": len(ipv4), "ipv6": len(ipv6), "domains": len(domains),
            "urls": len(urls), "emails": len(emails), "md5": len(md5),
            "sha1": len(sha1), "sha256": len(sha256), "ssdeep": len(ssdeep),
            "registry_paths": len(registry),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from unstructured text.")
    parser.add_argument("--file", "-f", help="Input file (omit to read stdin)")
    parser.add_argument("--output", "-o", help="Output JSON file (omit to print)")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    result = extract(text)
    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        total = sum(result["counts"].values())
        print(f"Extracted {total} indicators -> {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
