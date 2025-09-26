# Month 1 (Weeks 1–4): Foundations of Cybersecurity & Incident Response

## 🎯 Objectives

By the end of Month 1, you should be comfortable with:

- Key security & IR concepts (kill chain, MITRE ATT&CK, incident flow)
- Basics of threat intelligence (TTPs, IOCs/IOAs)
- Reading and interpreting logs (Windows, Sysmon, Linux)
- Understanding basic network traffic (TCP/IP, DNS, HTTP/S)
- Having a working lab setup (Windows + Linux + log collection + SIEM/monitoring)

---

## 📘 Concepts & Theory to Cover (Week-wise)

| Week   | Topics & Concepts |
|--------|------------------|
| **Week 1** | **Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain**<br>- Understand each stage of the kill chain (Recon, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives).<br>- MITRE ATT&CK: tactics, techniques, sub-techniques, mapping adversary behavior.<br>- Pyramid of Pain: which IOCs adversaries care about, and how defenders should prioritize detection. |
| **Week 2** | **Incident Response Lifecycle**<br>- Preparation, Detection & Analysis, Containment, Eradication, Recovery, Lessons Learned.<br>- What your role is in each phase; coordinating with teams; logging, playbooks, escalation paths. |
| **Week 3** | **Threat Intelligence Basics**<br>- TTPs (Tactics, Techniques, Procedures), IOCs (Indicators of Compromise), IOAs (Indicators of Attack).<br>- Threat intelligence lifecycle (collection, processing, analysis, dissemination).<br>- CTI standards (e.g. STIX/TAXII). |
| **Week 4** | **Log & Network Fundamentals (theory refresher and deeper dive)**<br>- Windows Event Logs, Sysmon events, Linux syslog / journald / auth logs.<br>- Network stack: OSI vs TCP/IP models; how DNS works; HTTP/HTTPS basics; packets, flows, ports, TCP handshake, etc.<br>- How logs and network data relate (e.g. flow records, packet captures). |

---

## 🧪 Hands-on / Lab Exercises

Below is a suggested lab plan for each week. You can use a local virtualization environment (VirtualBox, VMware) or cloud lab (AWS, Azure, GCP) if you prefer.

| Week   | Lab Tasks / Platform Ideas |
|--------|---------------------------|
| **Week 1** | 1. Set up your lab:<br> • Create two VMs: one Windows (e.g. Windows 10) and one Linux (e.g. Ubuntu).<br> • Add a “monitoring node” VM (Ubuntu) to host SIEM / log aggregator / network sniffer.<br>2. On Windows VM, enable basic Windows Event Logs, install Sysinternals tools (Process Explorer, Autoruns, TCPView, etc.).<br>3. On Linux VM, generate logs (e.g. via `sudo apt update`, logins, etc.), inspect `/var/log`.<br>4. (Optional) Deploy Security Onion or ElastAlert in your monitoring VM to receive logs. |
| **Week 2** | 1. Install Sysmon (on Windows VM). Configure a basic Sysmon config (process creation, network connection events).<br>2. Trigger a few benign actions: run applications, open browser, connect to web, etc. Observe which Sysmon events appear.<br>3. Forward Windows logs (EventLog + Sysmon) to your monitoring VM (via NXLog, Winlogbeat, or equivalent).<br>4. On monitoring VM, ingest logs into a simple open-source SIEM or log aggregator (e.g. ELK stack, Graylog). |
| **Week 3** | 1. Explore a TryHackMe “Threat Intelligence / CTI” room (e.g. “Intro to Cyber Threat Intel”).<br>2. Collect IOCs from free feeds (e.g. AlienVault OTX, MalwareBazaar), save them.<br>3. Attempt to detect those IOCs in your logs (if your lab is generating relevant data).<br>4. Write a mini threat intel report: topic, collected IOCs, what TTPs they map to. |
| **Week 4** | 1. Use tcpdump or Wireshark on your monitoring VM to capture packets between VMs.<br>2. Generate simple DNS/HTTP traffic (browse some websites) and analyze packet captures.<br>3. Correlate a network flow to a log event (e.g. Windows VM makes an HTTP request; see it in logs + packet capture).<br>4. Document sample network flow → source IP / dest IP / port / protocol, and link it to system logs. |

---

## 📚 Resources, Notes & GitHub References

### PDFs & Books / Reading Material

- **The Practice of Network Security Monitoring** by Richard Bejtlich — a core reference for network monitoring, incident detection & response. (No Starch Press)
- “Network Security Monitoring Rationale” (Chapter 1 excerpt) PDF from No Starch sample.
- **NIST SP 800-92**: Guide to Computer Security Log Management — useful guidelines on log collection, storage, retention.
- “A Tutorial on Network Security: Attacks and Controls” — gives you network threats & mitigations. (arXiv)

> ⚠️ Note: Always use proper/licensed sources for books. If a free PDF is legally available, that’s fine; otherwise purchase or use library versions.

---

### GitHub Repos / Writeups / Learning Paths

- [migueltc13 / TryHackMe](https://github.com/migueltc13/TryHackMe) — a repo collecting TryHackMe rooms & solutions.
- [ShubhamJagtap2000 / TryHackMe-THM](https://github.com/ShubhamJagtap2000/TryHackMe-THM) — structured path from “Introduction to Cybersecurity” → “Network Fundamentals” → “How the Web Works”, etc.
- [0xRad1ant/Tryhackme-Rooms](https://github.com/0xRad1ant/Tryhackme-Rooms) — curated TryHackMe room listings.
- [TryHackMe-Learning-Path-From-Beginner-to-Expert](https://github.com/0xRadiant/TryHackMe-Learning-Path-From-Beginner-to-Expert) — structured roadmap of rooms you can follow.

These repos are great for inspiration/reference: see how others structure notes, scripts, or solution writeups. You can clone them and adapt.

---

### Lab Platforms & Tools

- [TryHackMe](https://tryhackme.com/) — browser-based labs, both offensive and defensive. Great for practicing in a sandbox.
- [Security Onion](https://securityonion.net/) — free Linux distro for network security monitoring/intrusion detection (includes Zeek, Suricata, etc.).
- **ELK Stack (Elasticsearch, Logstash, Kibana)** — for log ingestion, search, visualization.
- **Graylog** — another open-source log management/SIEM platform.
- **Sysinternals Suite** — Windows utilities like Process Explorer, Autoruns, etc.
- **tcpdump / Wireshark** — packet capture and analysis.
- **Zeek** — network security monitoring/traffic analysis tool.

---

## 🗂️ Sample GitHub Notes & Portfolio Setup (for Month 1)

While you work through Month 1, you can keep a GitHub repo for your “Foundations” section. Here’s a sample structure:

```
month1-foundations/
├── notes/
│   ├── kill_chain_mitre_attack.md
│   ├── ir_lifecycle.md
│   ├── threat_intel_basics.md
│   ├── network_basics.md
│   └── log_analysis_windows_linux.md
├── lab_exercises/
│   ├── sysmon_lab/
│   │   ├── sysmon_config.xml
│   │   └── observations.md
│   ├── packet_capture_lab/
│   │   ├── capture.pcap
│   │   └── analysis.md
│   ├── logs_ingestion_lab/
│   │   ├── ELK_setup_notes.md
│   │   └── search_queries.md
│   └── threat_intel_lab/
│       ├── collected_iocs.txt
│       └── mini_report.md
└── README.md
```

- In `notes/` you summarize the theory in your own words (with diagrams).
- In `lab_exercises/` store configs, data captures, your analyses, observations, and explanations.
- In `README.md`, mention how to navigate the repo, what labs you’ve done, what you learned.

> Over time, this becomes part of your Blue Team Portfolio.
