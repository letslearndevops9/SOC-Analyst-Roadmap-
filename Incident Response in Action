“Incident Response in Action” module. It includes concepts, skills, step-by-step lab exercises (ransomware simulation, phishing analysis, chain-of-custody), recommended TryHackMe rooms, and authoritative PDF resources (NIST / SANS / CISA). I added inline citations to the main resources so you can copy this straight into your repo.

Safety note: always run the labs in an isolated, snapshot-able lab environment. Never run live malware on production or internet-connected hosts.

# Incident Response in Action — README

**Module:** Incident Response in Action  
**Duration:** 4 weeks (recommended)  
**Goal:** Learn and practice live response, containment, eradication & recovery, and professional incident reporting. Produce 2–3 case writeups (PDF) and include chain-of-custody documents for each case.

---

## Objectives
- Understand digital forensics fundamentals and evidence handling.  
- Practice live response data collection and chain-of-custody.  
- Run an IR simulation (ransomware exercise), analyze phishing emails, and document end-to-end incident reports.  
- Produce artifacts and deliverables for your GitHub portfolio.

---

## Concepts (summary)
- **Digital forensics basics:** evidence collection, imaging, volatile vs non-volatile data, hash verification.  
- **Containment strategies:** network isolation, account disablement, blocking IOCs at perimeter.  
- **Eradication & recovery:** reimaging, patching, credential resets, validating system integrity.  
- **Reporting & documentation:** technical timeline, executive summary, remediation, lessons learned.  
(See NIST Incident Handling Guide for programmatic guidance.) :contentReference[oaicite:0]{index=0}

---

## Skills to demonstrate
- Live response: collect memory, process lists, network connections, running services.  
- Forensic imaging & hashing (disk images, memory dumps).  
- Incident report writing and case management (ticketing & escalation).  
- Proper chain-of-custody record keeping (see SANS / CISA templates). :contentReference[oaicite:1]{index=1}

---

## Hands-on Labs (overview)
1. **IR Simulation — Ransomware** (Atomic Red Team guided) — simulate & respond. :contentReference[oaicite:2]{index=2}  
2. **Phishing Email Analysis** — header parsing, attachment analysis, and containment. :contentReference[oaicite:3]{index=3}  
3. **Chain-of-Custody Practice** — use form templates and practice transferring, sealing, and logging evidence. :contentReference[oaicite:4]{index=4}

---

## Lab A — IR Simulation: Ransomware (step-by-step)

> **Prereqs:** isolated lab network, Windows target VM (snapshot), analyst VM (Linux/Windows), Sysmon installed on endpoints, EDR/SIEM connected (optional). Use Atomic Red Team with caution and only in lab environment. :contentReference[oaicite:5]{index=5}

**Goal:** Execute a controlled Atomic test for ransomware (ATT&CK T1486) and run an end-to-end IR playbook.

**Steps**
1. Snapshot the target VM and document snapshot ID (very important).  
2. Prepare logging: ensure Sysmon is installed with a baseline config (e.g., SwiftOnSecurity config) and that Event Logs are forwarded or collected.  
3. Acquire Invoke-Atomic (or clone Atomic Red Team) on the target (or execute safe tests only):  
   ```powershell
   # On Windows (lab, elevated PowerShell)
   Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
   Import-Module Invoke-AtomicRedTeam
   # List tests and find T1486 (ransomware) variants
   Invoke-AtomicTest -List


Read prerequisites for each atomic test — some require additional tools or will write files. 
GitHub
+1

4. Start packet capture on the sensor:

sudo tcpdump -i any -w /tmp/ransim.pcap host <victim_ip>


Run a single, documented atomic sub-test for T1486 (or a low-impact surrogate option). Record exact command and timestamp.

Observe detection signals: Sysmon Event ID 1 (Process Create), Event ID 13 (Registry set), Event ID 3 (Network connect). Correlate these with pcap and EDR telemetry.

Containment: isolate the VM (disconnect network), record time and person performing action.

Evidence collection (live response): collect memory and key artifacts (use WinPmem for memory, export relevant event logs):

# Example (WinPmem must be present and used in lab)
winpmem64.exe -o C:\forensics\memory.raw


Forensics & analysis: run Volatility to extract suspicious processes, network connections, or injected modules.

Eradicate & recover: restore the VM from the pre-attack snapshot, patch, rotate credentials, and validate with scans.

Produce an Incident Report (see template below) and fill chain-of-custody for all artifacts collected.

Deliverables (commit to GitHub lab folder)

capture.pcap (trimmed), memory.raw (trimmed), volatility_output/ files, ioc.txt, incident-report.pdf, chain-of-custody.pdf.

Lab B — Phishing Email Analysis (step-by-step)

Goal: Analyze a phishing email (headers + attachment), extract IOCs, and document remediation steps.

Steps

Obtain or generate a phishing sample in the lab (TryHackMe has interactive phishing rooms). 
TryHackMe

Save the full raw email (.eml) and open headers. Inspect Received headers top-to-bottom to identify sender path and originating IPs. Look for SPF/DKIM/DMARC results.

Analyze attachments safely (do not open macros in a normal environment). Use tools: oletools / oledump.py for Office docs, pdfid/pdf-parser for PDFs, strings and antivirus scans. Example:

# Example: oledump
oledump.py suspicious.doc > oledump.out
# Strings/hash
strings suspicious.doc | head
sha256sum suspicious.doc


If attachment is an archive, extract in offline VM; if it drops a binary, hash it and search VirusTotal (or local offline malware lab).

Check logs for related host activity (process creation, network connections) and block C2 domains / IPs.

Document timeline: time received, time opened (if applicable), attachments, IOCs, and containment steps (blocked sender, reset passwords, user notification).

Deliverables

email_raw.eml, attachment_hashes.txt, analysis_notes.md, IOC_playbook.md.

Lab C — Chain-of-Custody & Evidence Handling (step-by-step)

Goal: Practice filling chain-of-custody for digital artifacts and transferring custody in a lab scenario. Use official templates for practice. 
SANS Institute
+1

Steps

Use a Chain-of-Custody template (SANS or NIST sample). Print or use a PDF editor to record entries. 
SANS Institute
+1

For each collected artifact (pcap, memory image, disk image), record:

Item number & description

Date/time collected (ISO 8601)

Collected by (name, role)

Location (lab host / snapshot ID)

Hash (SHA256)

If transferring artifact to another analyst (e.g., to a forensic specialist), record transfer with signatures (or digital signatures) and purpose of transfer.

Seal physical media (if applicable) with tamper-evident labels and record serial numbers in the form.

Store artifacts in an evidence locker (or dedicated secure directory) and reflect storage location on the form.

Keep a scanned copy of the chain-of-custody in the GitHub case folder (redacted to remove sensitive internal details).

Incident Report Template (short)

Title + Short summary (1–2 lines)

Impact (systems/users)

Timeline (detailed timestamps)

Evidence collected (files, hashes, snapshots)

Technical analysis (findings & ATT&CK mapping)

Containment & eradication actions taken

Recovery steps & verification results

Lessons learned & recommendations

(For programmatic IR guidance, see NIST SP 800-61r3.) 
NIST Publications

TryHackMe — Related Rooms (recommended)

Blue (Windows attack/defense practice — part of Blue Primer). 
TryHackMe

Phishing Analysis Fundamentals (email headers & attachments). 
TryHackMe

Phishing Analysis Tools (premium room with tool walkthroughs). 
TryHackMe

Splunk 2 (Boss of the SOC / Blue Primer) (SOC practice & correlation). 
TryHackMe

Security Operations & Monitoring module (SIEM/EDR fundamentals). 
TryHackMe

Key PDFs & Authoritative References

NIST SP 800-61r3 — Incident Response Recommendations & Considerations (guidance & best practices). 
NIST Publications

SANS White Papers & Case Studies — collection of IR case studies & templates. 
SANS Institute
+1

SANS Chain-of-Custody form (sample PDF) — good template for practice. 
SANS Institute

CISA Insights — Chain of Custody & CI Systems — overview and considerations for digital chain-of-custody. 
CISA

Atomic Red Team (for safe adversary emulation in labs) — use for ransomware & TTP simulations (lab only). 
GitHub
+1

How to document the lab in GitHub

Folder pattern:

labs/incident-response/
├─ lab-ransomware-2025-09-XX/
│  ├─ capture.pcap
│  ├─ memory.raw (trimmed)
│  ├─ volatility/
│  ├─ ioc.txt
│  ├─ chain-of-custody.pdf
│  └─ incident-report.pdf


Commit notes: redact secrets and internal IPs before pushing. Add a short lab-README.md that lists the exact commands and snapshot IDs used to reproduce the exercise (lab only).

Final checklist (for each IR lab)

 Snapshots taken before any test run

 Sysmon / logging baseline recorded

 Raw artifacts collected + SHA256 hashes saved

 Chain-of-custody filled for each artifact (signed)

 Incident report (PDF) with timeline and ATT&CK mapping

 Detections added/tuned in SIEM (if applicable)
