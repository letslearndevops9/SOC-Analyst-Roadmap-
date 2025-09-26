# Incident Response in Action — README

> **Safety Note:** Always run the labs in an isolated, snapshot-able lab environment. **Never** run live malware on production or internet-connected hosts.

## Module Overview

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

## Concepts (Summary)

- **Digital forensics basics:** evidence collection, imaging, volatile vs non-volatile data, hash verification.
- **Containment strategies:** network isolation, account disablement, blocking IOCs at perimeter.
- **Eradication & recovery:** reimaging, patching, credential resets, validating system integrity.
- **Reporting & documentation:** technical timeline, executive summary, remediation, lessons learned.  
  (See [NIST Incident Handling Guide][1] for programmatic guidance.)

---

## Skills to Demonstrate

- Live response: collect memory, process lists, network connections, running services.
- Forensic imaging & hashing (disk images, memory dumps).
- Incident report writing and case management (ticketing & escalation).
- Proper chain-of-custody record keeping (see [SANS][2] / [CISA][3] templates).

---

## Hands-on Labs (Overview)

- **IR Simulation — Ransomware** (Atomic Red Team guided) — simulate & respond.  
- **Phishing Email Analysis** — header parsing, attachment analysis, and containment.
- **Chain-of-Custody Practice** — use form templates and practice transferring, sealing, and logging evidence.

---

## Lab A — IR Simulation: Ransomware (Step-by-Step)

**Prereqs:**  
- Isolated lab network  
- Windows target VM (snapshot)  
- Analyst VM (Linux/Windows)  
- Sysmon installed on endpoints  
- EDR/SIEM connected (optional)  
- Use Atomic Red Team with caution and **only in lab environment** ([Atomic Red Team][4])

**Goal:** Execute a controlled Atomic test for ransomware ([ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)) and run an end-to-end IR playbook.

### Steps

1. **Snapshot the target VM** and document snapshot ID (very important).
2. **Prepare logging:** ensure Sysmon is installed with a baseline config (e.g., [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)) and that Event Logs are forwarded or collected.
3. **Acquire Invoke-Atomic (or clone Atomic Red Team) on the target (lab only):**
    ```powershell
    Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
    Import-Module Invoke-AtomicRedTeam
    # List tests and find T1486 (ransomware) variants
    Invoke-AtomicTest -List
    ```
    > Read prerequisites for each atomic test — some require additional tools or will write files.

4. **Start packet capture on the sensor:**
    ```bash
    sudo tcpdump -i any -w /tmp/ransim.pcap host <victim_ip>
    ```
5. **Run a single, documented atomic sub-test for T1486** (or a low-impact surrogate option). Record exact command and timestamp.
6. **Observe detection signals:**  
   - Sysmon Event ID 1 (Process Create)  
   - Event ID 13 (Registry set)  
   - Event ID 3 (Network connect)  
   - Correlate these with pcap and EDR telemetry.
7. **Containment:** Isolate the VM (disconnect network), record time and person performing action.
8. **Evidence collection (live response):** collect memory and key artifacts (use WinPmem for memory, export relevant event logs):
    ```powershell
    winpmem64.exe -o C:\forensics\memory.raw
    ```
9. **Forensics & analysis:** run Volatility to extract suspicious processes, network connections, or injected modules.
10. **Eradicate & recover:** restore the VM from the pre-attack snapshot, patch, rotate credentials, and validate with scans.
11. **Produce an Incident Report** (see template below) and fill chain-of-custody for all artifacts collected.

**Deliverables** (commit to GitHub lab folder):
- `capture.pcap` (trimmed)
- `memory.raw` (trimmed)
- `volatility_output/` files
- `ioc.txt`
- `incident-report.pdf`
- `chain-of-custody.pdf`

---

## Lab B — Phishing Email Analysis (Step-by-Step)

**Goal:** Analyze a phishing email (headers + attachment), extract IOCs, and document remediation steps.

### Steps

1. **Obtain or generate a phishing sample in the lab** (TryHackMe has interactive phishing rooms).
2. **Save the full raw email (.eml)** and open headers. Inspect `Received` headers top-to-bottom to identify sender path and originating IPs. Look for SPF/DKIM/DMARC results.
3. **Analyze attachments safely** (do not open macros in a normal environment). Use:
    - `oletools` / `oledump.py` for Office docs
    - `pdfid` / `pdf-parser` for PDFs
    - `strings` and antivirus scans

    Example:
    ```bash
    oledump.py suspicious.doc > oledump.out
    strings suspicious.doc | head
    sha256sum suspicious.doc
    ```

4. **If attachment is an archive, extract in offline VM;** if it drops a binary, hash it and search VirusTotal (or local offline malware lab).
5. **Check logs for related host activity** (process creation, network connections) and block C2 domains / IPs.
6. **Document timeline:** time received, time opened (if applicable), attachments, IOCs, and containment steps (blocked sender, reset passwords, user notification).

**Deliverables:**
- `email_raw.eml`
- `attachment_hashes.txt`
- `analysis_notes.md`
- `IOC_playbook.md`

---

## Lab C — Chain-of-Custody & Evidence Handling (Step-by-Step)

**Goal:** Practice filling chain-of-custody for digital artifacts and transferring custody in a lab scenario. Use official templates for practice ([SANS][2]).

### Steps

1. **Use a Chain-of-Custody template** ([SANS][2] or [NIST][1] sample). Print or use a PDF editor to record entries.
2. **For each collected artifact (pcap, memory image, disk image), record:**
    - Item number & description
    - Date/time collected (ISO 8601)
    - Collected by (name, role)
    - Location (lab host / snapshot ID)
    - Hash (SHA256)
3. **If transferring artifact** to another analyst (e.g., to a forensic specialist), record transfer with signatures (or digital signatures) and purpose of transfer.
4. **Seal physical media** (if applicable) with tamper-evident labels and record serial numbers in the form.
5. **Store artifacts in an evidence locker** (or dedicated secure directory) and reflect storage location on the form.
6. **Keep a scanned copy of the chain-of-custody in the GitHub case folder** (redacted to remove sensitive internal details).

---

## Incident Report Template (Short)

- **Title + Short summary (1–2 lines)**
- **Impact** (systems/users)
- **Timeline** (detailed timestamps)
- **Evidence collected** (files, hashes, snapshots)
- **Technical analysis** (findings & ATT&CK mapping)
- **Containment & eradication actions taken**
- **Recovery steps & verification results**
- **Lessons learned & recommendations**

> (For programmatic IR guidance, see [NIST SP 800-61r3][1].)

---

## TryHackMe — Related Rooms (Recommended)

- Blue (Windows attack/defense practice — part of Blue Primer)
- Phishing Analysis Fundamentals (email headers & attachments)
- Phishing Analysis Tools (premium room with tool walkthroughs)
- Splunk 2 (Boss of the SOC / Blue Primer) (SOC practice & correlation)
- Security Operations & Monitoring module (SIEM/EDR fundamentals)

---

## Key PDFs & Authoritative References

- **[NIST SP 800-61r3][1]** — Incident Response Recommendations & Considerations (guidance & best practices)
- **[SANS White Papers & Case Studies][2]** — collection of IR case studies & templates
- **[SANS Chain-of-Custody form (sample PDF)][5]** — good template for practice
- **[CISA Insights — Chain of Custody & CI Systems][3]** — overview and considerations for digital chain-of-custody
- **[Atomic Red Team][4]** — for safe adversary emulation in labs (ransomware & TTP simulations)

---

## How to Document the Lab in GitHub

**Folder pattern:**
```
labs/incident-response/
 ├─ lab-ransomware-2025-09-XX/
 │   ├─ capture.pcap
 │   ├─ memory.raw (trimmed)
 │   ├─ volatility/
 │   ├─ ioc.txt
 │   ├─ chain-of-custody.pdf
 │   └─ incident-report.pdf
```

**Commit notes:**  
- Redact secrets and internal IPs before pushing.
- Add a short `lab-README.md` that lists the exact commands and snapshot IDs used to reproduce the exercise (lab only).

---

## Final Checklist (for each IR lab)

- [ ] Snapshots taken before any test run
- [ ] Sysmon / logging baseline recorded
- [ ] Raw artifacts collected + SHA256 hashes saved
- [ ] Chain-of-custody filled for each artifact (signed)
- [ ] Incident report (PDF) with timeline and ATT&CK mapping
- [ ] Detections added/tuned in SIEM (if applicable)

---

## References

1. [NIST Incident Handling Guide (SP 800-61r3)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
2. [SANS Institute White Papers, Case Studies, and Chain-of-Custody Template](https://www.sans.org/white-papers/)
3. [CISA Insights: Chain of Custody](https://www.cisa.gov/sites/default/files/publications/insight-21-101-chains-of-custody-508.pdf)
4. [Atomic Red Team (GitHub)](https://github.com/redcanaryco/atomic-red-team)
5. [SANS Chain-of-Custody Form (PDF Sample)](https://www.sans.org/posters/sample-chain-of-custody-form/)
