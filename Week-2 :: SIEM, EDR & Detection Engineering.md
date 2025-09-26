# SIEM, EDR & Detection Engineering – Module Overview

Welcome to the SIEM, EDR & Detection Engineering module (Month 2). This module covers foundational concepts, practical skills, and hands-on labs to help you master Security Operations workflows, with suggested resources and a sample project structure to organize your learning.

---

## 🧠 Concepts to Cover

- **What is SIEM, SOAR, and EDR**
  - **SIEM (Security Information and Event Management):** Collects, normalizes, correlates, alerts, and stores logs/events from many sources for forensics.
  - **SOAR (Security Orchestration, Automation, and Response):** Automates workflows with playbooks, integrating multiple tools for rapid response.
  - **EDR (Endpoint Detection & Response):** Monitors endpoint activity (processes, files, memory, network) to detect, investigate, and respond to host threats.

- **How they complement each other:**  
  SIEM provides broad visibility, EDR offers detailed endpoint telemetry, SOAR automates responses.

- **Rule Creation & Tuning**
  - Writing detection rules (alerts, thresholds, patterns)
  - Tuning for false positive reduction & context enrichment
  - Rule lifecycle: draft → test → deploy → monitor → tune → retire
  - Rule evasion/blind spots (attackers may evade naive rules)

- **Detection Methodologies: Signature vs Behavioral**
  - Signature-based: fixed patterns, hashes, known indicators
  - Behavioral/anomaly-based: deviations from baseline, heuristics
  - Hybrid: combining signatures + behavior

- **Correlation & Threat Hunting Queries**
  - Correlating events across systems (endpoint + network + logs)
  - Building queries that tie together multiple signals
  - Using threat intelligence/IOCs to enrich detection

---

## 🛠️ Skills & Tools to Learn / Practice

- **SIEM Query Languages / DSLs**
  - Splunk SPL (search, stats, join, transaction, timechart, alerting)
  - ELK/Elasticsearch Query DSL, Kibana visualizations, alert rules

- **EDR Tools / Platforms**
  - Commercial: CrowdStrike Falcon, Microsoft Defender, etc.
  - Open Source: Velociraptor, Osquery

- **Correlation & Hunting Queries**
  - Chaining low-suspicion signals into high-confidence detection
  - Combining endpoint/network/log data

---

## 🧪 Hands-on / Lab Exercises

| Lab / Task                        | Description |
|------------------------------------|-------------|
| Set up SIEM & ingest logs          | Use Splunk (free) or ELK. Ingest Windows, Sysmon, Linux, open source logs. |
| Load BOTS dataset                  | Use Splunk BOSS of the SOC (BOTS) v3 dataset. |
| Write correlation rules/alerts     | Examples: brute force, lateral movement, persistence. |
| Create dashboards & alerts         | Build login trend dashboards, set alert rules in SIEM. |
| Integrate “EDR-like” telemetry     | Simulate endpoint telemetry, feed into SIEM, build correlation rules. |
| Participate in BOTS CTF / Blue Team| Use BOTS or BlueTeam Labs for real-world practice. |

---

## 📄 Related Notes, PDFs & Resources

- [The Essential Guide to SIEM (PDF)](https://www.exclusive-networks.com/wp-content/uploads/2022/03/The-Essential-Guide-to-SIEM.pdf) – SIEM fundamentals, log aggregation, EDR logs.
- [EDR Buyer’s Guide (PDF)](https://www.opentext.com/file_source/OpenText/en_US/PDF/opentext-edr-buyers-guide.pdf) – EDR roles and capabilities.
- [XDR vs. SIEM: A Cybersecurity Leader’s Guide (PDF)](https://www.secureworks.com/resources/white-papers/xdr-vs-siem-a-cybersecurity-leaders-guide) – Evolving architectures and SIEM’s role.
- [Analysing EDR Logs With SIEM Integration (Scribd)](https://www.scribd.com/document/540663738/Analysing-EDR-Logs-With-SIEM-Integration)
- **BOTS Writeups & Repos:**  
  - [chan2git/splunk-bots (walkthroughs)](https://github.com/chan2git/splunk-bots)  
  - [BOTS v3 dataset (official)](https://github.com/splunk/botsv3)  
  - [Corelight Trickbot CTF writeup](https://infosecwriteups.com/corelight-trickbot-ctf-walkthrough-2021-2fef8e5b848d)
- [Boss of the SOC v1: Threat Hunting with Splunk (Project)](https://samsclass.info/123/proj14/p-bots.htm)

---

## 📂 Sample Note / GitHub Structure for This Module

```
module_siem_detection/
├── notes/
│   ├── siem_edr_overview.md
│   ├── rule_tuning_best_practices.md
│   └── detection_methodologies.md
├── labs/
│   ├── bots_setup/
│   │   ├── bots_dataset_instructions.md
│   │   └── sample_searches.md
│   ├── correlation_rules/
│   │   ├── brute_force_rule.yml
│   │   └── lateral_movement_rule.md
│   ├── dashboards/
│   │   └── login_trend_dashboard.json
│   └── edr_integration/
│       └── endpoint_logs_to_siem.md
└── README.md
```

- **notes/**: Summarize concepts and methodologies in your own words.
- **labs/**: Include config files, queries, alert rules, observations, and screenshots.
- **README.md**: Explains lab setup, how to import BOTS dataset, and your workflow.

---

## 📝 Next Steps

- Integrate this module into your weekly plan.
- Use the provided structure to organize your learning and project files.
- [Optional] Want a detailed 4-week (Month 2) plan and Markdown templates for notes/rules? Let me know!

---
