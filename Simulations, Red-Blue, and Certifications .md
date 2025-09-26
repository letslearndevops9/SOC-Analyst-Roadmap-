# Simulations, Red-Blue, and Certifications 

**Module:** Simulations, Red-Blue, and Certifications  
**Duration:** 4 weeks (recommended)  
**Goal:** Learn purple-teaming basics, run adversary emulations (Caldera / Atomic Red Team), perform end-to-end IR exercises in a lab, measure SOC effectiveness (MTTD / MTTR), and build a certification roadmap + portfolio evidence for hiring.

> ⚠️ Safety first: **only run adversary emulation and malware tests in isolated, snapshot-able lab networks**. Never run live offensive tooling on production or Internet-connected systems.

---

## TL;DR (what you’ll produce)
- 2–3 purple-team lab reports (Markdown + PDF) showing: simulation → detection → response → lessons learned.  
- A small red-team toolbench in a lab (Caldera / Atomic Red Team) and step-by-step runbooks.  
- Measurable SOC KPIs for each exercise (MTTD, MTTR) and a short retrospective on how to improve them.  
- Portfolio artifacts: incident reports, playbooks, detection rules, and TryHackMe / CTF badges.  

---

## Why this matters (key references)
- Use MITRE Caldera for automated adversary emulation (ATT&CK-aligned). :contentReference[oaicite:0]{index=0}  
- Use Atomic Red Team for small, mapped ATT&CK tests you can safely run in a lab. :contentReference[oaicite:1]{index=1}  
- TryHackMe has practical blue/purple labs and SOC learning paths (Blue, Splunk/BOTS, SOC Level 2). :contentReference[oaicite:2]{index=2}

---

## Concepts (quick notes)
- **Purple teaming:** collaborative exercises where red-team activities are executed and blue-team detection/response is iteratively improved. Use ATT&CK to plan and map tests. :contentReference[oaicite:3]{index=3}  
- **Adversary emulation vs red-team:** emulation automates known TTPs to validate detection coverage; red-team engagements are often higher fidelity & scope. :contentReference[oaicite:4]{index=4}  
- **SOC effectiveness metrics:** MTTD (Mean Time To Detect) and MTTR/MTTS (Mean Time To Respond/Resolve). Track these before/after exercises to measure improvement. :contentReference[oaicite:5]{index=5}

---

## Skills to show
- Run automated adversary emulation and interpret outputs (Caldera, Atomic). :contentReference[oaicite:6]{index=6}  
- Execute purple-team cycles: plan (ATT&CK) → emulate → detect → tune → repeat. :contentReference[oaicite:7]{index=7}  
- Produce measurable improvements: reduced MTTD / MTTR and better detection coverage. :contentReference[oaicite:8]{index=8}  
- Build portfolio artifacts: incident reports, detection rules (Sigma/YARA/Splunk), and after-action reviews.

---

## Hands-on Labs (step-by-step)

### Lab 1 — **Caldera adversary emulation (automated red-team)**
**Goal:** Run an automated ATT&CK emulation, capture telemetry, and validate detections.

**Prep**
1. Isolate a lab network. Snapshot all VMs.  
2. Analyst VM (Linux) with network visibility; one or more target VMs (Windows/Linux).  
3. (Optional) SIEM (Splunk/ELK) and EDR (Velociraptor, Osquery) in lab.

**Install & run (high level)**
```bash
# clone Caldera (follow Caldera docs for exact current install steps)
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
# follow docs: install requirements and start the server (see linked Caldera docs)
# example: python3 -m pip install -r requirements.txt 
# then run: python server.py --insecure
Follow the official Caldera install docs for exact commands and options. 
caldera.readthedocs.io
+1

Exercise

Create an adversary profile (or use a shipped adversary) mapped to ATT&CK techniques you want to test.

Schedule a single, short emulation run against a snapshot target. Record timestamps.

Monitor SIEM/EDR and collect all alerts, logs, and network captures.

Produce a short report: which techniques were detected, which weren’t, MTTD for each detected technique, and recommended detection improvements.

Deliverables

Caldera run config, attack timeline, raw logs/alerts, pcap (trimmed), detection gaps list.

Lab 2 — Atomic Red Team: targeted atomic tests → detection tuning
Goal: Run specific atomic tests (e.g., persistence, command & control), verify detections, and create tuned rules.

Steps

Clone Atomic Red Team &/or install Invoke-AtomicRedTeam for PowerShell orchestration. 
GitHub
+1

bash
Copy code
git clone https://github.com/redcanaryco/atomic-red-team.git
# or on Windows use Invoke-AtomicRedTeam PowerShell module as documented
Pick 1–2 atomic tests (e.g., T1547 persistence, T1071 app-layer C2). Note prerequisites.

Snapshot the victim VM, start pcap capture on sensor, run the atomic test, and capture logs.

Triage: map alerts to ATT&CK, calculate MTTD, and write/update a Sigma/Splunk rule. Example: if persistence was missed, write a Sigma rule for registry autorun detection.

Re-run the test and measure improvements (new MTTD / detection rate).

Deliverables

Atomic test commands, logs, before/after MTTD, Sigma & Splunk rules.

Lab 3 — Purple Team exercise: live collaboration (red & blue together)
Goal: Run a transparent (full-knowledge) attack where red explains techniques in real time and blue tunes detections.

Flow

Plan scope & success criteria (which ATT&CK techniques to test, allowed impact). 
Picus Security

Red executes a pre-agreed atomic scenario while Blue observes & documents missed telemetry.

After each step: pause → discuss → implement detection tweaks (SIEM / EDR) → continue.

At the end: produce an AAR (after-action report) mapping improvements and updated KPIs (MTTD / MTTR).

Deliverables

Purple team plan, runbook, detection deltas (what changed), AAR.

Lab 4 — CTF / Blue Team practice & validation
Goal: Validate skills and earn demonstrable achievements.

Suggested TryHackMe rooms & paths

Blue (Windows hands-on) — good starter Blue exercise. 
TryHackMe

Splunk 2 / BOTS style rooms — SOC challenge / Boss of the SOC dataset practice. 
TryHackMe

SOC Level 2 path — progression towards a Level-2 SOC analyst role. 
TryHackMe

Flow

Complete 1–2 rooms, extract screenshots & write a short case study for each.

For each room, document detection hunts, rules written, and lessons learned.

Measuring SOC / IR effectiveness (MTTD, MTTR)
MTTD (Mean Time To Detect): how quickly your tooling + analysts detect activity from first malicious action. Track per technique to prioritize improvements. 
Arctic Wolf

MTTR (Mean Time To Respond/Resolve): time from detection to containment & recovery. Use post-exercise measurements to show improvement. 
Atlassian

How to measure (simple method)

For each exercise, record timestamps: attack start, first alert, containment action, full recovery.

Compute MTTD = avg(alert_time − attack_start). Compute MTTR = avg(recovery_time − alert_time).

Track changes across runs to demonstrate progress.

Certifications to consider (roadmap + links)
Beginner

CompTIA Security+ — baseline security certification (good for entry-level demonstration). 
CompTIA
+1

Blue Team Level 1 (BTL1) — community / vendor learning tracks (TryHackMe style). 
TryHackMe

Intermediate / Professional

GIAC GCFA — Forensic Analyst (memory & disk forensics). 
giac.org

GIAC GCIA — Intrusion Analyst (network/host traffic analysis). 
giac.org

GIAC GCTI — Cyber Threat Intelligence (threat hunting / intel). 
giac.org

Budget / Hands-on

TryHackMe SOC Level 2, CyberDefenders labs, BOTS practice rooms. 
TryHackMe
+1

GitHub repo layout (suggested)
bash
Copy code
simulations-red-blue/
├─ labs/
│  ├─ lab-caldera-emulation/
│  │  ├─ README.md        # this lab's playbook + commands
│  │  ├─ caldera-config/
│  │  └─ artifacts/       # pcap, logs, screenshots (trimmed)
│  ├─ lab-atomic-tests/
│  │  ├─ README.md
│  │  └─ detections/
│  └─ lab-purple-exercise/
│     ├─ plan.md
│     └─ aar.pdf
├─ detections/
│  ├─ sigma/
│  └─ splunk/
├─ metrics/
│  └─ soc-kpis.xlsx
└─ README.md   <-- this file
Deliverables checklist (per module)
 1 Caldera emulation runbook + artifacts

 2 Atomic Red Team test cases with before/after detection rules

 1 Purple team AAR with MTTD/MTTR measurement and detection deltas

 2 TryHackMe room case writeups (screenshots + learnings)

 Portfolio README linking all artifacts and certificate roadmap

Useful links & references
MITRE Caldera (project site & GitHub). 
caldera.mitre.org
+1

Atomic Red Team (official site & GitHub). 
atomicredteam.io
+1

TryHackMe — Blue room / Splunk / SOC Level 2 pages. 
TryHackMe
+2
TryHackMe
+2

CompTIA Security+ — official. 
CompTIA

GIAC cert pages (GCFA, GCIA, GCTI). 
giac.org
+2
giac.org
+2

Purple-team guidance / MITRE ATT&CK purple teaming resources. 
MITRE ATT&CK
+1

MTTD / MTTR definitions & measurement primer. 
Arctic Wolf
+1
