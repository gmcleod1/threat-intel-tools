# Threat Intelligence Report: {TITLE}

**Date:** {YYYY-MM-DD}
**Analyst:** Garfield McLeod
**TLP:** {WHITE | GREEN | AMBER | RED}
**Confidence:** {High | Medium | Low}

---

## Executive Summary

{2-4 sentences: what was observed, who/what is affected, the headline recommendation.}

## Indicators of Compromise

| Type | Indicator | VT Detections | Confidence | Notes |
|------|-----------|---------------|------------|-------|
| sha256 | {hash} | {mal/total} | {0-1} | {file name / family} |
| domain | {domain} | {mal/total} | {0-1} | {C2 / phishing} |
| ip-dst | {ip} | {mal/total} | {0-1} | {ASN / country} |
| url | {url} | {mal/total} | {0-1} | {payload / delivery} |

## Infrastructure Analysis

{C2 servers, hosting providers, ASN clustering, DNS/WHOIS, registration dates, overlaps with known campaigns.}

## Behavioral Analysis (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| {Execution} | {Command and Scripting Interpreter} | T1059 | {observation} |

## Threat Actor Profile (if applicable)

{Attribution confidence, objectives, known aliases, prior campaigns.}

## Recommendations

- **Detection:** {Sigma/YARA/SIEM rules to deploy}
- **Hunting:** {queries to run across the estate}
- **Defensive:** {blocks, hardening, user comms}

## Appendix

- Raw IOC export: `iocs.json`
- Enrichment export: `enriched-iocs.json`
- MISP event: `misp-event.json`
