# Threat Intelligence Tools

[![CI](https://github.com/gmcleod1/threat-intel-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/gmcleod1/threat-intel-tools/actions/workflows/ci.yml)

Automation for IOC extraction, enrichment, and reporting. Pulls indicators from unstructured text, enriches via VirusTotal/Shodan, formats for MISP and other platforms.

## Tools Overview

### IOC Extractor
Parses unstructured text (reports, logs, descriptions) and extracts structured indicators:
- **IP Addresses:** IPv4, IPv6 (excludes private/internal ranges)
- **Domains:** FQDN and subdomains
- **Hashes:** MD5, SHA1, SHA256, SSDEEP
- **URLs:** HTTP/HTTPS, file paths
- **Email Addresses:** User@domain format
- **Registry Paths:** Windows registry locations (malware persistence indicators)

Output: Structured JSON for further enrichment

### VirusTotal Enricher
Batch enrich indicators via VirusTotal API:
- File hashes: detection ratios, first submission, last submission, file names
- URLs: last submission date, SafeURL status
- Domains: DNS resolution history, WHOIS info
- IP addresses: ASN, country, threat categories

Output: Enriched IOC report with confidence scores

### MISP Formatter
Format IOCs for import into MISP (Malware Information Sharing Platform):
- Event creation with metadata
- Attribute standardization (MISP object types)
- Relationship mapping (file→URL→domain→IP)
- TLP and sharing restrictions
- Export to MISP JSON format

### STIX Formatter
Format IOCs as a STIX 2.1 bundle (for TAXII 2.1 collections or STIX-native platforms):
- One `Indicator` SDO per IOC, with a proper STIX pattern (`[ipv4-addr:value = '...']`, `[file:hashes.'SHA-256' = '...']`, etc.)
- A `Grouping` SDO ties all indicators in a run together as one reportable unit
- TLP applied via STIX `marking-definition` objects (white/green/amber/red)
- Built on the official [`stix2`](https://pypi.org/project/stix2/) library, so output validates against the STIX 2.1 spec

## Project Structure

```
threat-intel-tools/
  README.md                     # This file
  ioc-extractor.py              # Parse and extract indicators
  vt-enricher.py                # VirusTotal API integration
  misp-formatter.py             # Format for MISP platform
  stix-formatter.py             # Format as a STIX 2.1 bundle
  tests/                        # pytest suite (unit + end-to-end pipeline tests)
  .github/workflows/ci.yml     # CI: tests on Python 3.11-3.14
  config/
    vt-api-key.example.txt      # VirusTotal API key template
    misp-config.example.yml     # MISP instance config template
  reports/
    ioc-report-template.md      # Intelligence report template
    ioc-summary-template.txt    # Plaintext IOC list template
  examples/
    sample-report.txt           # Example malware report for IOC extraction
```

## Getting Started

### 1. Set up VirusTotal API
```bash
cp config/vt-api-key.example.txt config/vt-api-key.txt
# Add your VirusTotal API key to config/vt-api-key.txt
```

### 2. Extract IOCs from a report
```bash
python ioc-extractor.py --file reports/my-report.txt --output iocs.json
```

### 3. Enrich with VirusTotal
```bash
python vt-enricher.py --iocs iocs.json --output enriched-iocs.json
```

### 4. Generate intelligence report
```bash
python reports/build-report.py --enriched enriched-iocs.json --output threat-report.md
```

### 5. Format for sharing (MISP or STIX/TAXII)
```bash
python misp-formatter.py --iocs iocs.json --info "Emotet campaign 2026-06" --tlp amber --output misp-event.json
python stix-formatter.py --iocs iocs.json --name "Emotet campaign 2026-06" --tlp amber --output stix-bundle.json
```

## IOC Types and Examples

| Type | Examples | Use Case |
|------|----------|----------|
| File Hash (MD5) | `5d41402abc4b2a76b9719d911017c592` | Malware identification |
| File Hash (SHA256) | `2c26b46911185131006ba493dcf7b41b` | Malware tracking |
| IPv4 Address | `192.0.2.1`, `8.8.8.8` | C2 server, malware beacon |
| Domain | `evil.com`, `c2.attacker.com` | C2 infrastructure |
| URL | `http://evil.com/malware.exe` | Phishing, payload delivery |
| Email | `attacker@evil.com` | Threat actor contact |
| Registry Path | `HKLM\Software\Policies\Microsoft\Windows` | Persistence mechanism |
| File Path | `C:\Windows\Temp\bad.exe` | Malware location indicator |

## Workflow

1. **Collect** intelligence from various sources (reports, logs, analysis)
2. **Extract** structured IOCs from unstructured text
3. **Enrich** with VirusTotal, Shodan, WHOIS data
4. **Validate** indicators (false positives, expired infrastructure)
5. **Correlate** related indicators (file→URL→domain→IP)
6. **Report** findings with confidence scores and TLP
7. **Share** via MISP or other threat intelligence platform
8. **Track** effectiveness of indicators over time

## Intelligence Report Structure

Threat intelligence reports follow this standard structure:

- **Executive Summary:** High-level overview, affected parties, recommendations
- **Indicators of Compromise:** Structured IOC table with types and sources
- **Infrastructure Analysis:** C2 servers, hosting, DNS, WHOIS information
- **Behavioral Analysis:** MITRE ATT&CK techniques, capabilities
- **Threat Actor Profile:** (If applicable) Attribution, objectives, known campaigns
- **Recommendations:** Detection rules, defensive measures, threat hunting queries
- **Appendix:** Full technical details, raw data, analysis artifacts

## Testing

The pytest suite covers extraction regressions (defanging, private-IP filtering,
registry-path boundaries), STIX 2.1 output (every generated pattern is checked
against the official `stix2patterns` grammar validator, hive normalization,
TLP markings), MISP event structure, and end-to-end CLI runs including
error-path exit codes. CI runs the suite on Python 3.11–3.14 on every push.

```bash
pip install -r requirements-dev.txt
pytest
```

## Resources

- [VirusTotal API Documentation](https://developers.virustotal.com)
- [MISP Project](https://www.misp-project.org)
- [Shodan Search Engine](https://www.shodan.io)
- [Threat Intelligence Best Practices](https://www.misp-project.org/best-practices/)
- [TLP Traffic Light Protocol](https://www.first.org/tlp/)

## API Keys and Configuration

**IMPORTANT:** Never commit API keys or credentials to git.

Create local config files from templates:
```bash
cp config/vt-api-key.example.txt config/vt-api-key.txt
cp config/misp-config.example.yml config/misp-config.yml
```

These files are git-ignored and contain your personal credentials.

---

**Last Updated:** June 15, 2026
