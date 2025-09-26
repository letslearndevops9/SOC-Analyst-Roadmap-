# Simulations, Red-Blue, and Certifications

**Module:** Simulations, Red-Blue, and Certifications  
**Duration:** 4 weeks (recommended)  
**Goal:** Learn purple-teaming basics, run adversary emulations (Caldera / Atomic Red Team), perform end-to-end IR exercises in a lab, measure SOC effectiveness (MTTD / MTTR), and build a certification roadmap + portfolio evidence for hiring.

> ⚠️ **Safety first:** Only run adversary emulation and malware tests in isolated, snapshot-able lab networks. Never run live offensive tooling on production or Internet-connected systems.

---

## TL;DR — What You’ll Produce

- 2–3 purple-team lab reports (Markdown + PDF) showing: simulation → detection → response → lessons learned.
- A small red-team toolbench in a lab (Caldera / Atomic Red Team) and step-by-step runbooks.
- Measurable SOC KPIs for each exercise (MTTD, MTTR) and a short retrospective on how to improve them.
- Portfolio artifacts: incident reports, playbooks, detection rules, and TryHackMe / CTF badges.

---

## Why This Matters (Key References)

- Use [MITRE Caldera](https://caldera.mitre.org/) for automated adversary emulation (ATT&CK-aligned).
- Use [Atomic Red Team](https://atomicredteam.io/) for small, mapped ATT&CK tests you can safely run in a lab.
- [TryHackMe](https://tryhackme.com/) has practical blue/purple labs and SOC learning paths (Blue, Splunk/BOTS, SOC Level 2).

---

## Concepts (Quick Notes)

- **Purple teaming:** Collaborative exercises where red-team activities are executed and blue-team detection/response is iteratively improved. Use ATT&CK to plan and map tests.
- **Adversary emulation vs red-team:** Emulation automates known TTPs to validate detection coverage; red-team engagements are often higher fidelity & scope.
- **SOC effectiveness metrics:** MTTD (Mean Time To Detect) and MTTR/MTTS (Mean Time To Respond/Resolve). Track these before/after exercises to measure improvement.

---

## Skills to Show

- Run automated adversary emulation and interpret outputs (Caldera, Atomic).
- Execute purple-team cycles: plan (ATT&CK) → emulate → detect → tune → repeat.
- Produce measurable improvements: reduced MTTD / MTTR and better detection coverage.
- Build portfolio artifacts: incident reports, detection rules (Sigma/YARA/Splunk), and after-action reviews.

---

## Hands-on Labs (Step-by-Step)

### Lab 1 — **Caldera Adversary Emulation (Automated Red-Team)**

**Goal:** Run an automated ATT&CK emulation, capture telemetry, and validate detections.

**Prep:**
1. Isolate a lab network. Snapshot all VMs.
2. Analyst VM (Linux) with network visibility; one or more target VMs (Windows/Linux).
3. _(Optional)_ SIEM (Splunk/ELK) and EDR (Velociraptor, Osquery) in lab.

**Install & Run (High Level):**
```bash
# Clone Caldera (follow Caldera docs for exact current install steps)
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
# Follow docs: install requirements and start the server
# Example:
python3 -m pip install -r requirements.txt
python server.py --insecure
# See: https://caldera.readthedocs.io/en/latest/ for full instructions
```

**Exercise:**
- Create an adversary profile (or use a shipped adversary) mapped to ATT&CK techniques you want to test.
- Schedule a single, short emulation run against a snapshot target. Record timestamps.
- Monitor SIEM/EDR and collect all alerts, logs, and network captures.
- Produce a short report: which techniques were detected, which weren’t, MTTD for each detected technique, and recommended detection improvements.

**Deliverables:**
- Caldera run config, attack timeline, raw logs/alerts, pcap (trimmed), detection gaps list.

---

### Lab 2 — **Atomic Red Team: Targeted Atomic Tests → Detection Tuning**

**Goal:** Run specific atomic tests (e.g., persistence, command & control), verify detections, and create tuned rules.

**Steps:**
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
# Or on Windows use Invoke-AtomicRedTeam PowerShell module as documented
```
- Pick 1–2 atomic tests (e.g., T1547 persistence, T1071 app-layer C2). Note prerequisites.
- Snapshot the victim VM, start pcap capture on sensor, run the atomic test, and capture logs.
- Triage: map alerts to ATT&CK, calculate MTTD, and write/update a Sigma/Splunk rule.
- Re-run the test and measure improvements (new MTTD / detection rate).

**Deliverables:**
- Atomic test commands, logs, before/after MTTD, Sigma & Splunk rules.

---

### Lab 3 — **Purple Team Exercise: Live Collaboration (Red & Blue Together)**

**Goal:** Run a transparent (full-knowledge) attack where red explains techniques in real time and blue tunes detections.

**Flow:**
- Plan scope & success criteria (which ATT&CK techniques to test, allowed impact).
- Red executes a pre-agreed atomic scenario while Blue observes & documents missed telemetry.
- After each step: pause → discuss → implement detection tweaks (SIEM / EDR) → continue.
- At the end: produce an AAR (after-action report) mapping improvements and updated KPIs (MTTD / MTTR).

**Deliverables:**
- Purple team plan, runbook, detection deltas (what changed), AAR.

---

### Lab 4 — **CTF / Blue Team Practice & Validation**

**Goal:** Validate skills and earn demonstrable achievements.

**Suggested TryHackMe Rooms & Paths:**
- Blue (Windows hands-on) — good starter Blue exercise.
- Splunk 2 / BOTS style rooms — SOC challenge / Boss of the SOC dataset practice.
- SOC Level 2 path — progression towards a Level-2 SOC analyst role.

**Flow:**
- Complete 1–2 rooms, extract screenshots & write a short case study for each.
- For each room, document detection hunts, rules written, and lessons learned.

---

## Measuring SOC / IR Effectiveness: MTTD & MTTR

- **MTTD (Mean Time To Detect):** How quickly your tooling + analysts detect activity from first malicious action. Track per technique to prioritize improvements.
- **MTTR (Mean Time To Respond/Resolve):** Time from detection to containment & recovery. Use post-exercise measurements to show improvement.

**How to measure (simple method):**
- For each exercise, record timestamps: attack start, first alert, containment action, full recovery.
- Compute MTTD = avg(alert_time − attack_start).
- Compute MTTR = avg(recovery_time − alert_time).
- Track changes across runs to demonstrate progress.

---

## Certifications to Consider (Roadmap + Links)

**Beginner:**
- [CompTIA Security+](https://www.comptia.org/certifications/security) — baseline security certification (good for entry-level demonstration).
- [Blue Team Level 1 (BTL1)](https://tryhackme.com/) — community/vendor learning tracks (TryHackMe style).

**Intermediate / Professional:**
- [GIAC GCFA](https://www.giac.org/certifications/forensic-analyst-gcfa/) — Forensic Analyst (memory & disk forensics).
- [GIAC GCIA](https://www.giac.org/certifications/intrusion-analyst-gcia/) — Intrusion Analyst (network/host traffic analysis).
- [GIAC GCTI](https://www.giac.org/certifications/cyber-threat-intelligence-gcti/) — Cyber Threat Intelligence (threat hunting / intel).

**Budget / Hands-on:**
- TryHackMe SOC Level 2, CyberDefenders labs, BOTS practice rooms.

---

## GitHub Repo Layout (Suggested)

```
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
```

---

## Deliverables Checklist (Per Module)

- [ ] Caldera emulation runbook + artifacts
- [ ] Atomic Red Team test cases with before/after detection rules
- [ ] Purple team AAR with MTTD/MTTR measurement and detection deltas
- [ ] 2 TryHackMe room case writeups (screenshots + learnings)
- [ ] Portfolio README linking all artifacts and certificate roadmap

---

## Useful Links & References

- [MITRE Caldera: project site & GitHub](https://caldera.mitre.org/)
- [Atomic Red Team: official site & GitHub](https://atomicredteam.io/)
- [TryHackMe — Blue room / Splunk / SOC Level 2 pages](https://tryhackme.com/)
- [CompTIA Security+ — official](https://www.comptia.org/certifications/security)
- [GIAC cert pages (GCFA, GCIA, GCTI)](https://www.giac.org/)
- [Purple-team guidance / MITRE ATT&CK purple teaming resources](https://attack.mitre.org/resources/purple-team-exercises/)
- [MTTD / MTTR definitions & measurement primer](https://arcticwolf.com/resources/blog/mttd-mttr-cybersecurity-metrics/)
