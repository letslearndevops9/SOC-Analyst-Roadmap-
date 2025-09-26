Advanced Threat Hunting & Automation — README.md

Module: Advanced Threat Hunting & Automation
Duration: 4 weeks (recommended)
Goal: Learn to operationalize threat intelligence, author YARA & Sigma detections, automate enrichment and log parsing, and ship detection artifacts into a SIEM pipeline (Sigma → Splunk/ELK). Produce reusable scripts, Sigma/YARA rules, and at least one automated IOC enrichment notebook for your GitHub portfolio.

Quick resource highlights: Sigma (rule format & converters), Florian Roth’s rule collections (YARA / IOCs), MISP/OpenCTI (TIPs), AlienVault OTX & VirusTotal APIs for enrichment. 
VirusTotal Docs
+4
GitHub
+4
GitHub
+4

Concepts (short)

Threat intel feeds & enrichment: ingest IOCs from TIPs (MISP, OpenCTI) and public feeds (AlienVault OTX); enrich IOCs with VirusTotal / OTX metadata to prioritize. 
GitHub
+2
GitHub
+2

Advanced hunting with YARA & Sigma: use YARA to detect binary/memory artifacts and Sigma to express platform-agnostic log detections; convert Sigma → Splunk/ELK with Sigma converters. 
GitHub
+1

Automation: use Python & PowerShell to parse logs, extract IOCs, call enrichment APIs (VirusTotal / OTX), and automatically open incidents or create SIEM alerts.

Skills to build

Write reliable YARA rules for common malware families and generic suspicious patterns. (See Florian Roth / neo23x0 repos for examples). 
GitHub

Build expressive Sigma rules and convert them to Splunk / ELK queries using Sigma CLI / pySigma. 
sigmahq.io

Script automation: Python for API calls & parsing; PowerShell for Windows endpoint automation and evidence collection.

Create a Sigma→Splunk pipeline (repo + CI job) to test and push converted rules into a lab Splunk instance.

Hands-on Labs (step-by-step)

Lab environment: isolated lab network with Windows victim(s), Linux analyst/sensor, and a SIEM (Splunk Free or ELK). Keep snapshots.

Lab 1 — Build Sigma → Splunk pipeline (deliverable: tools/sigma-pipeline/)

Goal: Convert Sigma rules to Splunk and push into your Splunk lab automatically.

Steps

Install Sigma CLI (or pySigma) locally or in a container (see Sigma resources).

Create a local sigma/ directory with sample rules (copy detections/sigma/*.yml).

Create a script to convert all Sigma → Splunk SPL:

# example using sigma-cli (pseudo)
sigma convert -t splunk -c config/splunk.yml sigma/*.yml -o converted/splunk/


(Use pySigma / sigmac tool; see Sigma docs for exact CLI flags). 
sigmahq.io

Commit converted SPL files to converted/splunk/. Create a small CI job (GitHub Actions) that on push calls a script to upload the SPL queries to Splunk via the REST API (or place into a monitored directory).

In Splunk lab, create saved searches from the uploaded SPL and attach alerts. Test by replaying BOTS dataset or your lab logs.

Deliverables

tools/sigma-pipeline/convert.sh (or Python wrapper)

converted/splunk/ (SPL files)

GitHub Actions workflow /.github/workflows/deploy-sigma.yml

Lab 2 — Write & test YARA rules (deliverable: detections/yara/)

Goal: Author YARA rules that catch a test malware sample or suspicious string patterns in memory/dumped files.

Steps

Pick an example (friendly test sample or LOKI/THOR sample). Use rule examples from Florian Roth / signature-base as inspiration. 
GitHub
+1

Create a YARA rule template detections/yara/generic-suspicious-strings.yar:

rule Suspicious_Powershell_Encoder
{
  meta:
    author = "Your Name"
    description = "Detect base64-encoded PowerShell one-liners in files or memory"
    date = "2025-09-26"
  strings:
    $enc1 = "powershell -enc" nocase
    $enc2 = "Invoke-Expression" nocase
  condition:
    any of ($enc*) 
}


Test rule locally with yara against a set of sample files or memory dumps:

yara -w detections/yara/generic-suspicious-strings.yar samples/ -r


If you want runtime scanning, integrate YARA into your pipeline (Loki/THOR or custom scanner).

Deliverables

YARA rules in detections/yara/ with README explaining test methodology and false positive notes.

Lab 3 — IOC enrichment automation (VirusTotal & OTX) (deliverable: tools/enrich/virus_otx_enrich.py)

Goal: Build a Python script that takes a list of IOCs (IPs, domains, hashes) and enriches them with VirusTotal and OTX metadata, outputting a prioritized CSV/JSON.

Steps

Create tools/enrich/requirements.txt (requests, python-dotenv).

Create .env with VT_API_KEY and OTX_API_KEY (don’t commit secrets).

Minimal Python snippet (replace <API_KEY> with env variable usage):

import os, requests, csv
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


Run the script with iocs.txt (one IOC per line) and produce enriched_iocs.csv with fields like ioc,type,vt_malicious_votes,otx_pulses,last_seen.

Use enrichment results to tag Sigma/Splunk alerts or to automatically create a prioritized ticket in your tracker.

Deliverables

tools/enrich/virus_otx_enrich.py (well-documented)

Sample iocs.txt and enriched_iocs.csv

References: VirusTotal & OTX API docs. 
VirusTotal Docs
+1

Lab 4 — Script IOC extraction from logs (deliverable: tools/parse_logs/parse_iocs.py)

Goal: Script that parses log files (Sysmon/Zeek/ELK exports) and extracts IOCs automatically.

Steps

Write parse_iocs.py that:

Accepts a log file (json/ndjson or CSV)

Regex-extracts IPs, domains, hashes, emails

Deduplicates and writes iocs_extracted.txt

Example regex snippets (Python):

import re
ip_re = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
hash_re = re.compile(r"\b[a-fA-F0-9]{64}\b")
domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")

def extract_iocs(text):
    return set(ip_re.findall(text)) | set(hash_re.findall(text)) | set(domain_re.findall(text))


Pipe parsed IOCs into tools/enrich/virus_otx_enrich.py for enrichment.

Deliverables

tools/parse_logs/parse_iocs.py + unit test examples

TryHackMe & other lab references

TryHackMe rooms / learning paths that map well to this module:

Threat Hunting with YARA (community writeups exist; use to practice YARA creation). 
Medium

SOC / Detection Engineering rooms (Sigma, SIEM-focused) — search TryHackMe for Sigma/SIEM content.

Handbooks & collections: Blue Team Handbook is a compact field guide for SOC/SIEM/hunting use-cases. 
Dokumen
+1

Sample Sigma rule (template)

Place this in detections/sigma/suspicious-ps-encoded.yml and use pySigma to convert.

title: Suspicious Encoded PowerShell Execution
id: 2a5b1c3d-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: experimental
description: Detects process creation where command line contains 'powershell -enc' or similar encoded flags.
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


Convert with Sigma CLI to Splunk/ELK and tune as needed. 
sigmahq.io

Sample YARA rule (template)

Place in detections/yara/powershell_encoded.yar:

rule Powershell_Encoded_OneLiner
{
  meta:
    author = "Your Name"
    description = "Detect common encoded PowerShell flags in scripts or memory"
    date = "2025-09-26"
  strings:
    $s1 = "-enc" nocase
    $s2 = "-EncodedCommand" nocase
    $s3 = "-nop -w hidden" nocase
  condition:
    any of them
}


Test with yara detections/yara/powershell_encoded.yar samples/ -r.

GitHub repo structure (recommended)
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

Notes & PDFs to include in repo

Link / store (small excerpts or links only) to:

Sigma project (official) — Sigma rule format & converters. 
GitHub
+1

Florian Roth / neo23x0 repos for rule examples (signature-base / yarGen). 
GitHub
+1

MISP & OpenCTI docs (TIP platforms). 
GitHub
+1

VirusTotal & OTX API docs (for enrichment automation). 
VirusTotal Docs
+1

Blue Team Handbook PDF (reference/read). 
Dokumen
+1

Keep PDFs as pointers/links if you cannot store them directly (copyright). When including snippets, keep under fair-use length and always cite.

Deliverables checklist (for this module)

 detections/yara/ — 3 tested YARA rules + test cases

 detections/sigma/ — 5 Sigma rules covering common TTPs (PowerShell, Persistence, Lateral Movement, RDP abuse, Data Exfil)

 tools/sigma-pipeline/ — conversion & deployment scripts + CI workflow

 tools/enrich/virus_otx_enrich.py — enrichment script with sample output

 tools/parse_logs/parse_iocs.py — log parser to extract IOCs

 Lab READMEs for reproducibility (commands, test data, snapshots)

Next steps (suggested)

Pick one Sigma rule and convert it to Splunk — commit converted SPL and test with replayed logs.

Pick one YARA rule and test against known samples (or safe test files).

Build enrichment script and run it on IOCs extracted from lab logs.

Add everything to your GitHub repo and create a short lab-report.pdf (Markdown → PDF) documenting methodology, tests, and results.

Helpful links (useful starting points)

Sigma project (rules & tools). 
GitHub
+1

Florian Roth / neo23x0 (YARA & detection resources). 
GitHub

MISP (Threat Intel Platform). 
GitHub

OpenCTI (Threat Intel Platform). 
GitHub

AlienVault OTX API docs. 
LevelBlue Open Threat Exchange

VirusTotal API docs. 
VirusTotal Docs

Blue Team Handbook (SOC/SIEM/Hunting notes). 
Dokumen
+1
