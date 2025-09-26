# Advanced Threat Hunting & Automation

**Module Duration:** 4 weeks (recommended)  
**Goal:** Learn to operationalize threat intelligence, author YARA & Sigma detections, automate enrichment and log parsing, and ship detection artifacts into a SIEM pipeline (Sigma → Splunk/ELK). Produce reusable scripts, Sigma/YARA rules, and at least one automated IOC enrichment notebook for your GitHub portfolio.

---

## Quick Resource Highlights

- **Sigma:** [sigmahq.io](https://sigmahq.io/) (rule format & converters)
- **Rule Collections:** Florian Roth’s [YARA](https://github.com/Neo23x0/signature-base) / [IOCs](https://github.com/Neo23x0/threat-intel)
- **TIPs:** [MISP](https://github.com/MISP/MISP), [OpenCTI](https://github.com/OpenCTI-Platform/opencti)
- **Enrichment APIs:** [AlienVault OTX](https://otx.alienvault.com/api), [VirusTotal](https://developers.virustotal.com/reference/overview)
- **Automation:** Python, PowerShell

---

## Concepts

- **Threat Intel Feeds & Enrichment:** Ingest IOCs from TIPs (MISP, OpenCTI) and public feeds (AlienVault OTX); enrich IOCs with VirusTotal / OTX metadata to prioritize.
- **Advanced Hunting with YARA & Sigma:** Use YARA to detect binary/memory artifacts and Sigma to express platform-agnostic log detections; convert Sigma → Splunk/ELK with Sigma converters.
- **Automation:** Use Python & PowerShell to parse logs, extract IOCs, call enrichment APIs, and automatically open incidents or create SIEM alerts.

---

## Skills to Build

- Write reliable **YARA rules** for common malware families and generic suspicious patterns. (See Florian Roth / neo23x0 repos for examples.)
- Build expressive **Sigma rules** and convert them to Splunk / ELK queries using Sigma CLI / pySigma.
- **Script automation:** Python for API calls & parsing; PowerShell for Windows endpoint automation and evidence collection.
- Create a **Sigma→Splunk pipeline** (repo + CI job) to test and push converted rules into a lab Splunk instance.

---

## Hands-on Labs

### Lab 1 — Build Sigma → Splunk Pipeline

**Goal:** Convert Sigma rules to Splunk and push into your Splunk lab automatically.

**Steps:**
1. Install Sigma CLI (or pySigma).
2. Create a local `sigma/` directory with sample rules.
3. Script conversion:  
   ```sh
   sigma convert -t splunk -c config/splunk.yml sigma/*.yml -o converted/splunk/
   ```
4. Commit SPL files. Create a CI job (GitHub Actions) to upload SPL queries to Splunk or place into a monitored directory.
5. In Splunk, create saved searches from uploaded SPL and attach alerts. Test with BOTS dataset or lab logs.

**Deliverables:**
- `tools/sigma-pipeline/convert.sh`
- `converted/splunk/` (SPL files)
- `.github/workflows/deploy-sigma.yml`

---

### Lab 2 — Write & Test YARA Rules

**Goal:** Author YARA rules that catch malware sample or suspicious patterns.

**Steps:**
1. Pick a test sample (friendly or from LOKI/THOR).
2. Create a YARA rule template (`detections/yara/generic-suspicious-strings.yar`):

   ```yara
   rule Suspicious_Powershell_Encoder
   {
     meta:
       author = "Your Name"
       description = "Detect base64-encoded PowerShell one-liners"
       date = "2025-09-26"
     strings:
       $enc1 = "powershell -enc" nocase
       $enc2 = "Invoke-Expression" nocase
     condition:
       any of ($enc*) 
   }
   ```

3. Test locally:
   ```sh
   yara -w detections/yara/generic-suspicious-strings.yar samples/ -r
   ```

**Deliverables:**
- YARA rules in `detections/yara/` with README

---

### Lab 3 — IOC Enrichment Automation

**Goal:** Build Python script to enrich IOCs with VirusTotal and OTX metadata.

**Steps:**
1. Create `tools/enrich/requirements.txt` (requests, python-dotenv).
2. Create `.env` with keys (do not commit secrets).
3. Python snippet:

   ```python
   import os, requests
   VT_KEY = os.getenv("VT_API_KEY")
   OTX_KEY = os.getenv("OTX_API_KEY")
   def vt_lookup_hash(h):
       url = f"https://www.virustotal.com/api/v3/files/{h}"
       headers = {"x-apikey": VT_KEY}
       r = requests.get(url, headers=headers)
       return r.json() if r.status_code==200 else None
   def otx_indicator(indicator):
       url = f"https://otx.alienvault.com/api/v1/indicators/ipv4/{indicator}/general"
       headers = {"X-OTX-API-KEY": OTX_KEY}
       r = requests.get(url, headers=headers)
       return r.json() if r.status_code==200 else None
   ```

4. Run the script with `iocs.txt`, produce `enriched_iocs.csv`.

**Deliverables:**
- `tools/enrich/virus_otx_enrich.py`
- Sample `iocs.txt` and `enriched_iocs.csv`

---

### Lab 4 — Script IOC Extraction from Logs

**Goal:** Script parses log files and extracts IOCs automatically.

**Steps:**
1. Write `tools/parse_logs/parse_iocs.py`:
   - Accepts log file (json/ndjson or CSV)
   - Regex-extracts IPs, domains, hashes
   - Deduplicates and writes `iocs_extracted.txt`
2. Example regex snippets (Python):

   ```python
   import re
   ip_re = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
   hash_re = re.compile(r"\b[a-fA-F0-9]{64}\b")
   domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
   def extract_iocs(text):
       return set(ip_re.findall(text)) | set(hash_re.findall(text)) | set(domain_re.findall(text))
   ```

3. Pipe parsed IOCs into enrichment script.

**Deliverables:**
- `tools/parse_logs/parse_iocs.py` + unit test examples

---

## TryHackMe & Lab References

- **TryHackMe rooms:** Threat Hunting with YARA, SOC/Detection Engineering (Sigma, SIEM-focused)
- **Handbook:** Blue Team Handbook (SOC/SIEM/hunting use-cases)

---

## Sample Sigma Rule

```yaml
title: Suspicious Encoded PowerShell Execution
id: 2a5b1c3d-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: experimental
description: Detects encoded PowerShell commandlines.
author: Your Name
date: 2025/09/26
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-nop -w hidden -e'
  condition: selection
falsepositives:
  - Admins running encoded scripts
level: medium
```

---

## Sample YARA Rule

```yara
rule Powershell_Encoded_OneLiner
{
  meta:
    author = "Your Name"
    description = "Detect common encoded PowerShell flags"
    date = "2025-09-26"
  strings:
    $s1 = "-enc" nocase
    $s2 = "-EncodedCommand" nocase
    $s3 = "-nop -w hidden" nocase
  condition:
    any of them
}
```

---

## Recommended Repo Structure

```
advanced-threat-hunting/
├─ detections/
│  ├─ sigma/
│  │  └─ suspicious-ps-encoded.yml
│  └─ yara/
│     └─ powershell_encoded.yar
├─ tools/
│  ├─ sigma-pipeline/
│  │  ├─ convert.sh
│  │  └─ deploy-to-splunk.sh
│  ├─ enrich/
│  │  └─ virus_otx_enrich.py
│  └─ parse_logs/
│     └─ parse_iocs.py
├─ labs/
│  ├─ lab-sigma-pipeline/README.md
│  └─ lab-yara-testing/README.md
└─ README.md  <-- this file
```

---

## Notes & PDFs to Include

- [Sigma project (rules & tools)](https://github.com/SigmaHQ/sigma)
- [Florian Roth / neo23x0](https://github.com/Neo23x0/signature-base) (YARA & detection resources)
- [MISP (Threat Intel Platform)](https://github.com/MISP/MISP)
- [OpenCTI (Threat Intel Platform)](https://github.com/OpenCTI-Platform/opencti)
- [AlienVault OTX API docs](https://otx.alienvault.com/api)
- [VirusTotal API docs](https://developers.virustotal.com/reference/overview)
- Blue Team Handbook (SOC/SIEM/Hunting notes) — link or fair-use excerpt only

---

## Deliverables Checklist

- `detections/yara/` — 3 tested YARA rules + test cases
- `detections/sigma/` — 5 Sigma rules (PowerShell, Persistence, Lateral Movement, RDP abuse, Data Exfil)
- `tools/sigma-pipeline/` — conversion & deployment scripts + CI workflow
- `tools/enrich/virus_otx_enrich.py` — enrichment script + sample output
- `tools/parse_logs/parse_iocs.py` — log parser for IOCs
- Lab READMEs for reproducibility

---

## Next Steps

1. Pick one Sigma rule, convert to Splunk, and test with replayed logs.
2. Pick one YARA rule and test against known samples.
3. Build enrichment script and run on IOCs from lab logs.
4. Add all to GitHub repo and create a short lab-report.pdf documenting methodology and results.

---

## Helpful Links

- [Sigma project](https://github.com/SigmaHQ/sigma)
- [Florian Roth / neo23x0](https://github.com/Neo23x0/signature-base)
- [MISP](https://github.com/MISP/MISP)
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti)
- [AlienVault OTX API docs](https://otx.alienvault.com/api)
- [VirusTotal API docs](https://developers.virustotal.com/reference/overview)
- Blue Team Handbook (SOC/SIEM/Hunting notes)

---
