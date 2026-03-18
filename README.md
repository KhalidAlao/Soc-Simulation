# SOC Simulation & Detection Engineering Project

**A Security Operations Center**  

<img width="950" height="351" alt="SOC Lab Architecture" src="https://github.com/user-attachments/assets/421d8da6-b104-4aa8-ab9d-8d1d86ce7033" />

## 📌 Project Overview
This project simulates a real‑world SOC for a mid‑sized investment firm. It includes:
- A **Wazuh SIEM** deployed on an Ubuntu VM (emulated on Apple Silicon)
- A **Kali Linux attacker VM** generating malicious traffic (SSH brute force)
- **Custom detection rules** mapped to MITRE ATT&CK
- **Incident response documentation** (executive report, playbook)
- **Governance artifacts** (log retention policy, RACI matrix, awareness metrics)

The goal was to build an end‑to‑end security operations workflow that demonstrates technical depth, process maturity, and business communication skills.

## 🖥️ Architecture
| Component | Description | IP Address |
|-----------|-------------|------------|
| Wazuh Server (Ubuntu) | SIEM (manager, indexer, dashboard) | `192.168.64.14` |
| Kali Linux | Attacker machine (brute force simulation) | `192.168.64.12` |
| Management Host | My Mac (Apple Silicon) | – |

All VMs run on UTM in emulation mode and communicate over a shared virtual network (`192.168.64.0/24`).

---

## 🔍 Detection Capabilities

### Custom Rule: SSH Brute Force
- **Rule ID**: `100001`
- **Trigger**: 3+ failed SSH attempts from the same source IP within 30 seconds
- **MITRE ATT&CK**: [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Response**: Automatic IP blocking via active response (iptables)

**Alert Screenshot**  
<img width="1226" height="727" alt="Rule Triggered" src="https://github.com/user-attachments/assets/e60822a8-e2af-4369-b180-f99d5138a1a2" />


**Rule Definition** (`detections/bruteforce-rule.xml`):
```xml
<rule id="100001" level="10" frequency="3" timeframe="30">
        <if_matched_sid>5760</if_matched_sid>
        <same_source_ip />
        <description>CRITICAL: Persistent SSH Brute Force Attack Detected: 3 failures from $(srcip)</description>
        <group>bruteforce,gdpr_IV_35.7.d,</group>
        <mitre>
            <id>T1110</id>
        </mitre>
    </rule>
