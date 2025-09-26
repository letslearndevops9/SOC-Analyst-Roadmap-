# Threat Hunting Playbook & Blue Team Portfolio

**TL;DR**  
This repository contains threat-hunting labs, playbooks, detection artifacts (Sigma/YARA/Splunk), and case writeups to demonstrate hands-on Incident Response (IR) and Threat Hunting skills. Each lab is designed to showcase end-to-end workflows, evidence collection, detection engineering, and reporting.

---

## Repo layout

```
threat-hunting-playbook/
├─ labs/
│  ├─ lab-a-pcap-analysis/
│  ├─ lab-b-memory-analysis/
│  └─ lab-c-persistence-registry/
├─ playbooks/
│  └─ persistence-hunt-playbook.md
├─ detections/
│  ├─ sigma/
│  │  └─ suspicious-runkey.yml
│  ├─ yara/
│  └─ splunk/
├─ case-studies/
│  └─ case-2025-09-26-runkey-infection.md
└─ README.md
```

---

## How to use this repo

1. Clone the repo to your analyst machine.
2. Read each lab's `README.md` for preconditions (VM images, snapshots).
3. Run labs in an isolated network. Always snapshot VMs before running adversary simulations.
4. For each lab: produce artifacts (pcap, memory dump snippets), a `case-README.md`, and detection artifacts (Sigma/YARA/Splunk queries).

---

## What this demonstrates

- Hypothesis-driven threat hunting mapped to MITRE ATT&CK
- Memory forensics (Volatility) and PCAP analysis (Zeek/Wireshark)
- Detection engineering (Sigma → platform conversions, SIEM alerts)
- End-to-end IR workflow (detect → contain → eradicate → recover → report)

---

## Quick links & useful resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Volatility 3](https://www.volatilityfoundation.org/)
- [Zeek (Bro)](https://zeek.org/)
- [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sigma project](https://github.com/SigmaHQ/sigma)

---

## Contribution / Notes

- Add a new folder under `labs/` for each exercise and include `case-README.md` and artifacts.
- Keep sensitive data out of the repo. Trim memory/pcap files before committing (include only trimmed or redacted artifacts).

---
