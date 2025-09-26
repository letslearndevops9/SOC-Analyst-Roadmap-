# Security & Incident Response (IR) Key Concepts and Labs

## 1. Key Security & IR Concepts

### Cyber Kill Chain
Describes the stages of a cyberattack:
- **Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives**
- Defenders can disrupt attacks at each stage.

### MITRE ATT&CK
A knowledge base mapping real-world adversary tactics/techniques to detection/mitigation.

### Incident Response (IR) Lifecycle Phases
- **Preparation**
- **Identification**
- **Containment**
- **Eradication**
- **Recovery**
- **Lessons Learned**

### IOC vs IOA
- **IOC**: Evidence of past attack (IP, hash, domain).
- **IOA**: Evidence of ongoing attack (e.g., suspicious process, lateral movement).

### Measuring SOC/IR
- **Metrics**: MTTD (Mean Time To Detect), MTTR (Mean Time To Respond), false positives, incident counts.

---

## Lab Exercise: Mapping Attack to Kill Chain & MITRE ATT&CK

**Goal:** Map simulated attack to Kill Chain & MITRE ATT&CK.

**Steps:**
1. **Setup:** Windows 10 VM + Kali Linux VM + SIEM (Wazuh/Splunk).
2. **Simulate attack:** (e.g., Metasploit exploit on Windows).
3. **Collect logs:** Windows Events, Sysmon, network traffic.
4. **Analyze logs:** Map to Kill Chain & MITRE ATT&CK.
5. **Capture screenshots** of detections.

**Sample Diagram:**
```
Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions
  |         |             |            |            |         |
  [Log1]  [Log2]       [Log3]       [Log4]       [Net1]   [Alert1]
```

---

## 2. Threat Intelligence (TTPs, IOCs/IOAs)

### Key Concepts
- **TTPs**: 
  - **Tactics** (goal)
  - **Techniques** (method)
  - **Procedures** (steps)
- **Gathering Threat Intel**: OSINT, CTI feeds, honeypots, SIEM, MITRE mapping.
- **SOC Use**: Prioritize alerts, block IOCs, detect patterns, custom rules.

### Lab Exercise: Detecting IOCs/IOAs

**Goal:** Detect IOCs/IOAs in logs.

**Steps:**
1. Configure Windows logging + Sysmon.
2. Generate simulated IOC (malicious hash/IP).
3. Query logs in SIEM for matches.

**Sample Splunk Query:**
```spl
index=windows sourcetype=Sysmon EventCode=1 Hashes="*malware_hash*"
```

---

## 3. Reading & Interpreting Logs

### Key Concepts

- **Suspicious Windows Activity:** Unexpected logons, new/odd processes, failed logons, privilege escalations.
- **Key Sysmon Events:** 
  - ProcessCreate (1)
  - NetworkConnect (3)
  - FileCreate (11)
  - RegistryEvent (13)
- **Linux Log Analysis:** 
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `journalctl`

### Lab Exercise: Detecting Suspicious Logins/Processes

**Goal:** Detect suspicious logins/processes.

**Steps:**
1. Generate activity (normal + malicious).
2. Analyze logs (Windows Event Viewer, Linux CLI).
3. Highlight anomalies.

**Sample Diagram:**
```
User Login → Log Event → SIEM Alert → Analyst Review → Response
```

---

## 4. Understanding Basic Network Traffic

### Key Concepts

- **Detecting Suspicious Traffic:** Unusual ports, external IPs, high volume, failed connects.
- **TCP vs UDP:**
  - **TCP:** Reliable, connection-oriented.
  - **UDP:** Fast, connectionless, unreliable.
- **DNS Abuse:** DGA, exfiltration, C2.
- **HTTP/S Monitoring:** Wireshark, Zeek, SIEM.

### Lab Exercise: Capture & Analyze Traffic

**Goal:** Capture/analyze traffic.

**Steps:**
1. Use Wireshark.
2. Simulate normal + malicious traffic.
3. Analyze sessions, headers, DNS queries.

**Sample Diagram:**
```
[Internal VM] → TCP/HTTP → [External IP] → SIEM Logs → Analyst Detection
```

---

## 5. Working Lab Setup

### Requirements

- **Windows VM** (endpoint logs, attacks)
- **Linux VM** (attack simulation, monitoring)
- **SIEM** (Wazuh, Splunk, ELK)
- **Log Collection** (Sysmon, auditd, Windows logs)
- **Network Monitoring** (Wireshark, Zeek)

### Sample Diagram
```
Windows VM ──┐
             │──> Log Forwarder ──> SIEM ──> Dashboard / Alerts
Linux VM ────┘
```

---

## Lab Practical Tasks for Interview

- Collect logs (Sysmon/auditd)
- Forward logs to SIEM
- Detect simulated malware or network anomalies
- Map to MITRE ATT&CK/Kill Chain
- Document with screenshots & response steps

---

## Interview Readiness Tips

- Prepare annotated screenshots (SIEM, process execution, network captures)
- Be ready to explain reasoning and mapping to frameworks
- Practice key commands:
  - **Windows:** `eventvwr`, `Get-EventLog`
  - **Linux:** `journalctl`, `tcpdump`, `netstat`
- Prepare diagrams for each scenario
