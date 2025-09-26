I built a focused, practical Threat Hunting Methodologies module with step-by-step lab exercises, ready-to-use commands, example detection artifacts (Sigma/Splunk), and a GitHub / case-writeup template so you can show hands-on work. I kept each lab executable in a small home/VM lab (Windows victim + Linux sensor/analyst + SIEM). I also pointed to authoritative resources you can download/read (PDFs, repos, docs).

What this contains

Quick concept recap (so you can write it into your notes)

5 hands-on labs (detailed step-by-step) you can run now — each includes commands, expected outputs, and what to document for your GitHub portfolio.

Example detection artifacts: a Sigma rule + Splunk hunts you can paste and test.

GitHub repo layout + case writeup template (what to include when publishing an exercise).

Key resources & downloads (Volatility, Atomic Red Team, WinPmem, Sysmon config, MITRE ATT&CK + more) so you can grab PDFs and code.

Concepts (short)

Hypothesis-driven hunting: form a hypothesis (e.g., “A user executed a downloader → network egress”), list data sources, run queries, iterate.

Map every hunt to MITRE ATT&CK technique(s) and to the Pyramid of Pain (IOCs → TTPs). 
MITRE ATT&CK
+1

Prioritize behavioral detections over static IOCs for long-term value.

Labs (step-by-step)

Setup note: isolate the lab network, snapshot VMs, and only run atomic tests you understand. Use a Windows VM (victim), a Linux VM as sensor/analyst (Zeek/tcpdump/Wireshark), and a SIEM VM (ELK or Splunk Free).

Lab A — Capture live attack traffic (Atomic Red Team → PCAP → Zeek/Wireshark)

Goal: generate network traffic for a known ATT&CK technique, capture it, analyze it, and map to ATT&CK.

Prep:

Install Zeek on your Linux sensor or run tcpdump on the bridge. (Zeek docs). 
Zeek Documentation

Install Atomic Red Team (or Invoke-Atomic) on the Windows victim. Atomic Red Team provides small atomic tests mapped to ATT&CK. 
GitHub
+1

Pick a safe atomic test that produces network traffic (e.g., T1105 Ingress Tool Transfer or T1071 Application Layer Protocol) and note the atomic ID. Example: run a single, documented atomic test via Invoke-Atomic:

On the Windows victim (PowerShell, elevated):

# Clone or download Invoke-AtomicRedTeam, then
Import-Module .\Invoke-AtomicRedTeam.psm1
# List tests
Invoke-AtomicTest -List
# Run a specific atomic test (example)
Invoke-AtomicTest -Technique T1105 -TestNumbers 1 -ShowDetails
# Or use the Invoke-Atomic runner per the project's README.


(See Invoke-AtomicRun docs for exact usage and local/remote options). 
GitHub

Capture the traffic (on sensor):

# capture all traffic to file
sudo tcpdump -i any -nn -s 0 -w /tmp/capture.pcap host <victim_ip>
# or use tshark to live-filter:
sudo tshark -i any -f "host <victim_ip>" -w /tmp/capture.pcap


Analyze with Zeek:

# convert pcap to zeek logs (conn.log, http.log, dns.log, etc.)
zeek -r /tmp/capture.pcap
# inspect logs
head conn.log
head http.log


Zeek will produce conn.log, http.log, dns.log you can review for unusual hosts, URIs, user agents. 
Zeek Documentation

Analyze with Wireshark:

Open /tmp/capture.pcap in Wireshark; use "Follow TCP Stream", use display filters such as http.request, dns, ip.addr==x.x.x.x. Wireshark sample captures are useful for practice. 
wiki.wireshark.org

Document (for GitHub):

Atomic test run command, pcap, Zeek logs, screenshots of suspicious HTTP requests and their timestamps, mapping to ATT&CK technique(s).

Write a short timeline: (time) -> process executed -> outbound HTTP GET -> domain -> file downloaded.

Lab B — Memory acquisition + Volatility (extract IOCs from memory)

Goal: capture ram from a compromised Windows VM, extract processes, strings, suspicious injected code, and YARA hits.

Acquire memory (use WinPmem or another forensically accepted tool). Example tools: WinPmem (Velocidex). 
winpmem.velocidex.com

On victim (elevated):

# if using winpmem-windows.exe (example)
winpmem64.exe -o C:\forensics\memory.raw


Transfer memory.raw to your analyst VM.

Run Volatility 3 to get OS info and process list:

# examples — command name may vary (python vol.py or vol3)
python3 vol.py -f memory.raw windows.info
python3 vol.py -f memory.raw windows.pslist


(Volatility 3 docs and Windows tutorial explain plugin names and usage). 
volatility3.readthedocs.io

Dump suspicious process memory (find suspicious PID from pslist then dump):

python3 vol.py -f memory.raw -o ./outdir windows.memmap --pid 1234 --dump


(Volatility3 uses windows.memmap with --dump to export process memory pages). 
Information Security Stack Exchange
+1

YARA/strings search in memory:

# run yara scans (volatility yarascan plugin)
python3 vol.py -f memory.raw windows.yarascan --yara-file rules.yar


(Volatility3 supports YARA scanning via a yarascan/vadyarascan plugin). 
volatility3.readthedocs.io

Extract registry hives (if present) and search for suspicious Run keys or autostart entries (Volatility has registry plugins windows.registry.printkey etc.).

Document:

Commands you ran, interesting strings, YARA matches, list of dumped files, extracted DLLs / injected code, and mapping to ATT&CK.

Lab C — Hunt for persistence (Windows registry / Sysmon)

Goal: find persistent autostart artifacts and correlate to process creation + network connections.

Ensure Sysmon is installed and running with a good config (use SwiftOnSecurity as a starting config). Install Sysmon on the Windows VM and use sysmonconfig-export.xml. 
GitHub

Install command (elevated):

sysmon64.exe -accepteula -i sysmonconfig-export.xml


Identify registry autostart locations (common keys):

HKLM:\Software\Microsoft\Windows\CurrentVersion\Run

HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce

Scheduled Tasks, Services, Startup folder. Use Autoruns for a GUI listing (Sysinternals Autoruns). 
Microsoft Learn

Query registry from PowerShell:

# HKLM Run keys
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' |
  Select-Object PSChildName, @{n='Value';e={$_.'(default)'}} 
# HKCU run keys
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'


(Microsoft PowerShell docs on Get-ItemProperty). 
Microsoft Learn

Hunt in logs:

Sysmon registry events: Sysmon produces Registry events (Event ID 12/13/14 etc). Event ID 13 = Registry value set (useful for autostart additions). Tune and filter because event 13 is noisy; correlate TargetObject and Image fields. 
Microsoft Learn

Example hunt (Splunk-ish pseudocode):

index=sysmon EventCode=13
| stats count by TargetObject, Image, Computer
| where like(TargetObject, "%\\CurrentVersion\\Run%")


Investigate the Image (process that wrote the key), the timestamp, and cross-reference with Sysmon process creation events (Event ID 1).

Document:

Registry keys found, process that wrote them, timeline, remediation suggestion (remove value, quarantine binary), and detection rule you created (example below).

Lab D — PCAP deep dive: reconstruct file downloads & C2

Goal: from the pcap created in Lab A, reconstruct HTTP downloads and any suspicious TLS metadata.

In Wireshark: Follow → TCP Stream on suspicious flows. Use display filters:

http.request, dns.qry.name contains "suspicious-domain", tls.handshake.extensions_server_name

Use tshark to extract HTTP hosts & URIs:

tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri


Use Zeek outputs (http.log, conn.log) to identify anomalies (unusual ports, long durations, repeated beaconing).

Document: HTTP request/response, file hash (if file transfer), mapping to ATT&CK.

Lab E — Create a hunting playbook & detection (Sigma → SIEM)

Goal: turn a hunting hypothesis into a reusable Sigma rule and test it.

Example hypothesis: “A non-Microsoft process writes to HKLM...\Run and spawns a child process that makes an outbound HTTP connection within 60 seconds.”

Example Sigma rule (YAML) — detects Sysmon Registry set to Run key + process creation:

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


Convert Sigma to platform queries using pySigma / sigma CLI (docs). 
sigmahq.io

Example Splunk correlation (rough):

index=sysmon (EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*")
| join type=left ProcessGuid [ search index=sysmon EventCode=3 | fields ProcessGuid, src_ip, dest_ip, _time as net_time ]
| where abs(_time - net_time) < 60
| table host, Image, TargetObject, src_ip, dest_ip, _time


Test & tune: run this against BOTS datasets or your lab sysmon logs. Iterate to reduce noise.

Example commands / cheatsheet (copyable)

Capture traffic: sudo tcpdump -i any -nn -s 0 -w capture.pcap host <victim_ip>

Zeek: zeek -r capture.pcap → conn.log, http.log, dns.log

Volatility 3 basics:

python3 vol.py -f memory.raw windows.info
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw -o out windows.memmap --pid 1234 --dump
python3 vol.py -f memory.raw windows.yarascan --yara-file rules.yar


(plugin names and invocation can vary by install; see Volatility3 docs). 
volatility3.readthedocs.io
+1

Sysmon install & example config:

sysmon64.exe -accepteula -i sysmonconfig-export.xml
# use SwiftOnSecurity sysmonconfig-export.xml as a starter


(SwiftOnSecurity config repo). 
GitHub

GitHub portfolio & case writeup template

Repo structure (recommended)

threat-hunting-playbook/
├─ labs/
│  ├─ lab-a-pcap-analysis/
│  │  ├─ README.md        # hypothesis, goal, ATT&CK mapping
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
│  └─ case-2025-09-26-runkey-infection.md
└─ README.md


Case writeup (README.md / case file) — sections

Title + short summary (1–2 lines)

Dates & environment (VM images, snapshots)

Hypothesis & ATT&CK mapping (technique IDs) — include tactic/technique IDs. 
MITRE ATT&CK

Data sources used (Sysmon, Windows Security, Zeek, PCAP, memory)

Step-by-step timeline with commands, outputs (screenshots/snippets)

Artifacts & IOCs (hashes, domains, IPs) — provide ioc.txt and downloadable artifacts (pcap, memory subsets) in the repo (redact secrets)

Detections written (Sigma file, Splunk query), false positives & tuning notes

Remediation & lessons learned

Link to any slides/PDF report

Recommended reference downloads & repos (PDFs / code)

Atomic Red Team (tests + mappings to ATT&CK). 
GitHub
+1

Volatility 3 docs (Windows tutorial + plugin list). 
volatility3.readthedocs.io
+1

WinPmem (memory acquisition). 
winpmem.velocidex.com

SwiftOnSecurity Sysmon config (sysmonconfig-export.xml). 
GitHub

Zeek docs (Book of Zeek for PCAP/NSM). 
Zeek Documentation

Wireshark SampleCaptures (practice PCAPs). 
wiki.wireshark.org

ThreatHunter-Playbook (playbooks & notebooks you can fork). 
GitHub

MITRE ATT&CK reference (map everything to ATT&CK). 
MITRE ATT&CK

Sigma rule project / converters (pySigma). 
GitHub

How to present this on your GitHub (quick tips)

Put a one-page TL;DR in the repo README.md describing skills shown (memory forensics, PCAP analysis, Sigma rule, Splunk query).

Include a PDF writeup for each case (case-YYYY-MM-DD.pdf) with screenshots and timelines.

Add a badge or index.md that lists which ATT&CK techniques each lab covers.

Add notebooks/ (Jupyter or plain Markdown) for playbooks so reviewers can read your step-by-step.

Final checklist (what to produce for a 1-page portfolio entry per lab)

 README with hypothesis + ATT&CK mapping. 
MITRE ATT&CK

 PCAP or memory sample (trimmed), plus analysis notes. 
wiki.wireshark.org
+1

 Detection rules (Sigma YAML + converted Splunk/ELK queries). 
GitHub

 Case writeup PDF (timeline, remediation, lessons learned).

 Link to reproducible lab steps (how to re-run atomic test) with safety note. 
GitHub
