# Threat Hunting Methodologies: Hands-On Labs & Portfolio Guide

## Overview

This module provides focused, practical threat hunting labs with step-by-step exercises, ready-to-use commands, example detection artifacts (Sigma/Splunk), and templates for your GitHub portfolio or case writeups.

---

### What’s Included

- **Quick Concept Recap:** Core hunting concepts to add to your notes.
- **5 Hands-On Labs:** Step-by-step guides for immediate use. Each lab provides commands, expected outputs, and documentation prompts for your portfolio.
- **Detection Artifacts:** Example Sigma rule & Splunk hunt to use/test.
- **Repo Layout & Writeup Template:** Guidance for publishing your work.
- **Key Resources & Downloads:** Tools, configs, and reference PDFs.

---

## Concepts (Summary)

- **Hypothesis-driven hunting:** 
  - Form a hypothesis (e.g., “A user executed a downloader → network egress”).
  - List data sources, run queries, iterate.
- **Map every hunt to MITRE ATT&CK technique(s) and the Pyramid of Pain (IOCs → TTPs).**
- **Prioritize behavioral detections over static IOCs for long-term value.**

---

## Labs: Step-by-Step

Each lab is designed for hands-on learning and portfolio documentation.

---

### Lab A — Capture Live Attack Traffic (Atomic Red Team → PCAP → Zeek/Wireshark)

**Goal:** Generate network traffic for a known ATT&CK technique, capture & analyze it, and map to ATT&CK.

#### Setup

- Isolate lab network, snapshot VMs.
- Use:
  - Windows VM (victim)
  - Linux VM (sensor/analyst, e.g., Zeek/tcpdump/Wireshark)
  - SIEM VM (ELK or Splunk, optional)

#### Steps

1. **Install Zeek** (Linux sensor) or use tcpdump.
2. **Install Atomic Red Team** (Windows victim).
3. **Run a safe atomic test** (e.g., T1105 Ingress Tool Transfer):

   ```powershell
   # Clone/download Invoke-AtomicRedTeam, then
   Import-Module .\Invoke-AtomicRedTeam.psm1
   Invoke-AtomicTest -List
   Invoke-AtomicTest -Technique T1105 -TestNumbers 1 -ShowDetails
   ```

4. **Capture Traffic** (sensor):

   ```bash
   sudo tcpdump -i any -nn -s 0 -w /tmp/capture.pcap host <victim_ip>
   # or
   sudo tshark -i any -f "host <victim_ip>" -w /tmp/capture.pcap
   ```

5. **Analyze with Zeek:**

   ```bash
   zeek -r /tmp/capture.pcap
   head conn.log
   head http.log
   ```

6. **Analyze with Wireshark:**
   - Open `capture.pcap`
   - Use filters: `http.request`, `dns`, `ip.addr==x.x.x.x`
   - “Follow TCP Stream” for suspicious flows

#### Documentation (for GitHub):

- Atomic test run command, pcap, Zeek logs, Wireshark screenshots
- Mapping to ATT&CK technique(s)
- Short timeline (process executed → HTTP GET → domain → file downloaded)

---

### Lab B — Memory Acquisition + Volatility

**Goal:** Capture RAM from a compromised Windows VM, extract processes, suspicious code, and YARA hits.

#### Steps

1. **Acquire memory:**  
   - Use WinPmem or similar.

     ```powershell
     winpmem64.exe -o C:\forensics\memory.raw
     ```

2. **Transfer `memory.raw` to analyst VM**

3. **Run Volatility 3:**

   ```bash
   python3 vol.py -f memory.raw windows.info
   python3 vol.py -f memory.raw windows.pslist
   python3 vol.py -f memory.raw -o ./outdir windows.memmap --pid 1234 --dump
   python3 vol.py -f memory.raw windows.yarascan --yara-file rules.yar
   ```

4. **Extract registry hives & search for persistence**

#### Documentation

- Commands, interesting strings, YARA matches, dumped files, mapping to ATT&CK

---

### Lab C — Hunt for Persistence (Registry/Sysmon)

**Goal:** Find persistent autostart artifacts; correlate with process creation/network connections.

#### Steps

1. **Install Sysmon (with SwiftOnSecurity config):**

   ```powershell
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```

2. **Identify registry autostart locations:**

   - `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
   - Use Autoruns for a GUI listing.

   ```powershell
   Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
   Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
   ```

3. **Hunt in logs:**  
   - Sysmon Event ID 13 for Registry set
   - Cross-reference with process creation (Event ID 1)
   - Example Splunk:

     ```splunk
     index=sysmon EventCode=13
     | stats count by TargetObject, Image, Computer
     | where like(TargetObject, "%\\CurrentVersion\\Run%")
     ```

#### Documentation

- Registry keys found, process, timeline, remediation suggestion, detection rule

---

### Lab D — PCAP Deep Dive: Reconstruct File Downloads & C2

**Goal:** From Lab A’s PCAP, reconstruct HTTP downloads & suspicious TLS metadata.

#### Steps

- **Wireshark:** Use “Follow TCP Stream”, filters: `http.request`, `dns.qry.name`, `tls.handshake.extensions_server_name`
- **tshark:**

  ```bash
  tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
  ```

- **Zeek outputs:** Review `http.log`, `conn.log` for anomalies

#### Documentation

- HTTP request/response, file hash (if transfer), ATT&CK mapping

---

### Lab E — Create a Hunting Playbook & Detection (Sigma → SIEM)

**Goal:** Turn a hunting hypothesis into a Sigma rule and test it.

#### Example Hypothesis

> “A non-Microsoft process writes to HKLM...\Run and spawns a child process that makes an outbound HTTP connection within 60 seconds.”

#### Example Sigma Rule

```yaml
title: Suspicious Run Key Added Followed By Network Activity
id: e1a12f3a-xxxx-xxxx-xxxx-xxxxxxxx
status: experimental
description: Detects a process writing to a Run key followed by a network connection from that process.
author: your.name
date: 2025/09/26
references:
  - https://github.com/SigmaHQ/sigma
tags:
  - attack.persistence
  - attack.T1547
logsource:
  product: windows
  service: sysmon
detection:
  selection_registry:
    SysmonEventID: 13
    TargetObject|contains: '\\CurrentVersion\\Run\\'
  selection_network:
    SysmonEventID: 3
  condition: selection_registry and selection_network
fields:
  - Image
  - TargetObject
falsepositives:
  - Legitimate installers/administrators
level: high
```

#### Splunk Correlation Example

```splunk
index=sysmon (EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*")
| join type=left ProcessGuid [ search index=sysmon EventCode=3 | fields ProcessGuid, src_ip, dest_ip, _time as net_time ]
| where abs(_time - net_time) < 60
| table host, Image, TargetObject, src_ip, dest_ip, _time
```

---

## Example Commands / Cheatsheet

- **Capture traffic:** `sudo tcpdump -i any -nn -s 0 -w capture.pcap host <victim_ip>`
- **Zeek:** `zeek -r capture.pcap`
- **Volatility 3:**  
  - `python3 vol.py -f memory.raw windows.info`
  - `python3 vol.py -f memory.raw windows.pslist`
  - `python3 vol.py -f memory.raw -o out windows.memmap --pid 1234 --dump`
  - `python3 vol.py -f memory.raw windows.yarascan --yara-file rules.yar`
- **Sysmon install:** `sysmon64.exe -accepteula -i sysmonconfig-export.xml`

---

## Recommended Repo Structure

```
threat-hunting-playbook/
├─ labs/
│  ├─ lab-a-pcap-analysis/
│  │  ├─ README.md
│  │  ├─ capture.pcap
│  │  ├─ zeek_logs/
│  │  └─ wireshark_notes.md
│  ├─ lab-b-memory-analysis/
│  │  ├─ README.md
│  │  ├─ memory.raw
│  │  ├─ volatility_output/
│  │  └─ yara_rules.yar
├─ playbooks/
│  ├─ persistence-hunt-playbook.md
├─ detections/
│  ├─ sigma/
│  │  └─ suspicious-runkey.yml
│  └─ splunk/
│     └─ runkey_correlation_search.txt
├─ case-studies/
│  └─ case-YYYY-MM-DD-runkey-infection.md
└─ README.md
```

---

## Case Writeup Template (README.md or case file)

- **Title + Short Summary**
- **Dates & Environment** (VM images, snapshots)
- **Hypothesis & ATT&CK Mapping** (technique IDs)
- **Data Sources Used** (Sysmon, Windows Security, Zeek, PCAP, memory)
- **Step-by-Step Timeline** (commands, outputs, screenshots)
- **Artifacts & IOCs** (hashes, domains, IPs; include ioc.txt, downloadable artifacts)
- **Detections Written** (Sigma, Splunk), false positives, tuning notes
- **Remediation & Lessons Learned**
- **Link to Slides/PDF Report**

---

## Key References & Downloads

- [Atomic Red Team (attack simulation)](https://github.com/redcanaryco/atomic-red-team)
- [Volatility 3 Docs](https://volatility3.readthedocs.io/)
- [WinPmem (memory acquisition)](https://winpmem.velocidex.com/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Zeek Documentation](https://docs.zeek.org/)
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rule Project](https://github.com/SigmaHQ/sigma)
- [ThreatHunter-Playbook](https://github.com/hunters-forge/ThreatHunter-Playbook)

---

## Portfolio Presentation Tips

- Add a one-page TL;DR to README.md (skills shown: memory forensics, PCAP analysis, Sigma rule, Splunk query).
- Include a PDF writeup for each case (case-YYYY-MM-DD.pdf) with screenshots and timeline.
- Add a badge or index.md listing which ATT&CK techniques each lab covers.
- Use notebooks/ for playbooks (Jupyter or Markdown).
- For each lab, produce:
  - README with hypothesis & ATT&CK mapping
  - PCAP or memory sample (trimmed), analysis notes
  - Detection rules (Sigma YAML & Splunk/ELK queries)
  - Case writeup PDF (timeline, remediation, lessons learned)
  - Link to reproducible lab steps (atomic test instructions & safety notes)

---
