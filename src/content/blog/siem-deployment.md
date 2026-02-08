---
title: "SIEM Deployment & Threat Detection - Wazuh & Splunk"
description: "Practical guide to deploying SIEM solutions using Wazuh and Splunk for threat detection, custom rules, and incident response workflows."
date: "2025-07-15"
category: "SOC / SIEM"
tags: ["SIEM", "Wazuh", "Splunk", "Threat Detection", "SOC"]
image: "/images/blog/siem-deployment.png"
imageAlt: "SIEM security operations center with Wazuh and Splunk dashboards"
author: "Rana Uzair Ahmad"
readTime: "14 min"
difficulty: "Intermediate"
---

Security Information and Event Management (SIEM) platforms are the backbone of any Security Operations Center. They aggregate logs from across your infrastructure, correlate events in real time, and surface the threats that matter. In this guide, I walk through deploying two of the most powerful SIEM solutions available — Wazuh (open-source) and Splunk (enterprise) — and show you how to write custom detection rules, build threat-hunting queries, and integrate with SOAR platforms for automated response.

## Understanding SIEM Architecture

A SIEM ingests data from endpoints, network devices, firewalls, cloud services, and applications. It normalizes those logs into a common schema, then applies correlation rules and statistical baselines to detect anomalies.

**Core Components:**

- **Log Collection** — Agents, syslog, API polling, and file-based ingestion.
- **Parsing & Normalization** — Converting vendor-specific formats into structured fields.
- **Correlation Engine** — Matching sequences of events against known attack patterns.
- **Alerting & Dashboards** — Real-time notifications and visual analytics.
- **Storage & Retention** — Indexed data for forensic investigation and compliance.

The key to a successful SIEM deployment is not just collecting logs — it is collecting the *right* logs, tuning rules to reduce noise, and building workflows that turn alerts into action.

## Wazuh: Open-Source SIEM & XDR

Wazuh has evolved from an OSSEC fork into a full-featured SIEM and Extended Detection and Response (XDR) platform. Its architecture is elegant and scalable.

### Wazuh Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Wazuh Agent │────▶│  Wazuh Manager   │────▶│  Wazuh Indexer│
│  (Endpoints) │     │  (Analysis)      │     │  (OpenSearch) │
└─────────────┘     └─────────────────┘     └──────────────┘
                            │                        │
                            ▼                        ▼
                    ┌─────────────┐         ┌──────────────┐
                    │  Filebeat    │         │  Wazuh        │
                    │  (Shipping)  │         │  Dashboard    │
                    └─────────────┘         └──────────────┘
```

### Deploying the Wazuh Stack

Install the Wazuh manager, indexer, and dashboard on a dedicated server. For production, separate these across multiple nodes.

```bash
# Download and run the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard

# Verify services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Agent Deployment

Deploy agents to every endpoint you want to monitor. Agents collect syslog, file integrity data, vulnerability inventory, and security configuration assessment results.

```bash
# Install agent on Ubuntu endpoint
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt-get update && apt-get install wazuh-agent

# Configure manager address
sed -i 's/MANAGER_IP/10.0.1.50/' /var/ossec/etc/ossec.conf
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

### Custom Wazuh Detection Rules

Wazuh rules are written in XML and follow a hierarchical structure. Each rule has a level (0–15), with higher levels indicating greater severity.

**Detecting Brute Force SSH Attacks:**

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="custom_ssh_bruteforce,">

  <rule id="100001" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <description>SSH brute force attack detected: 8+ failed logins in 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,brute_force,</group>
  </rule>

  <rule id="100002" level="12" frequency="15" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Aggressive SSH brute force: 15+ failures from same IP in 60 seconds</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

</group>
```

**Detecting Privilege Escalation via Sudo:**

```xml
<rule id="100010" level="10">
  <if_sid>5401</if_sid>
  <match>COMMAND=/bin/bash</match>
  <description>User escalated to root shell via sudo</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>privilege_escalation,</group>
</rule>

<rule id="100011" level="13">
  <if_sid>5402</if_sid>
  <regex>user NOT in sudoers</regex>
  <description>Unauthorized sudo attempt — possible privilege escalation</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
</rule>
```

**Detecting Suspicious PowerShell Execution on Windows:**

```xml
<rule id="100020" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName">powershell.exe</field>
  <regex>-enc|-EncodedCommand|-e </regex>
  <description>Encoded PowerShell execution detected — possible malware</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

### Filebeat Configuration for Log Shipping

Filebeat acts as the transport layer between the Wazuh manager and the indexer.

```yaml
# /etc/filebeat/filebeat.yml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

output.elasticsearch:
  hosts: ["https://10.0.1.50:9200"]
  protocol: https
  username: "admin"
  password: "${WAZUH_INDEXER_PASSWORD}"
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"
```

## Splunk: Enterprise SIEM

Splunk remains the industry standard for large-scale log analytics. Its Search Processing Language (SPL) is incredibly powerful for threat hunting.

### Splunk Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Universal    │────▶│  Heavy Forwarder  │────▶│  Indexer      │
│  Forwarder   │     │  (Parsing)        │     │  (Storage)    │
└──────────────┘     └──────────────────┘     └──────────────┘
                                                      │
                                                      ▼
                                              ┌──────────────┐
                                              │  Search Head  │
                                              │  (Analytics)  │
                                              └──────────────┘
```

### SPL Queries for Threat Detection

**Detecting Brute Force Attacks:**

```spl
index=auth sourcetype=linux_secure "Failed password"
| stats count as failed_attempts, values(src_ip) as source_ips by user
| where failed_attempts > 10
| sort -failed_attempts
| eval severity=case(
    failed_attempts > 50, "CRITICAL",
    failed_attempts > 25, "HIGH",
    failed_attempts > 10, "MEDIUM"
)
| table _time, user, source_ips, failed_attempts, severity
```

**Detecting Lateral Movement (Pass-the-Hash):**

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats count by src_ip, dest, user, Logon_Type
| where count > 5
| eval risk_score = count * 10
| lookup known_admin_workstations src_ip OUTPUT is_admin_ws
| where is_admin_ws != "true"
| sort -risk_score
| table src_ip, dest, user, count, risk_score
```

**Detecting Data Exfiltration via DNS:**

```spl
index=network sourcetype=dns
| eval query_length = len(query)
| where query_length > 50
| stats count as dns_requests, avg(query_length) as avg_len,
        dc(query) as unique_queries by src_ip
| where dns_requests > 500 AND avg_len > 60
| eval exfil_score = round((dns_requests * avg_len) / 1000, 2)
| sort -exfil_score
| table src_ip, dns_requests, avg_len, unique_queries, exfil_score
```

**Detecting Privilege Escalation on Windows:**

```spl
index=wineventlog (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| eval action=case(
    EventCode=4672, "Special privileges assigned",
    EventCode=4728, "User added to global security group",
    EventCode=4732, "User added to local security group"
)
| stats count by user, action, dest, _time
| sort -_time
| table _time, user, action, dest, count
```

## Threat Detection Use Cases

### 1. Brute Force Detection

Monitor authentication logs for repeated failed login attempts. Correlate across multiple services — an attacker failing on SSH may pivot to RDP or a web application.

### 2. Privilege Escalation

Watch for anomalous sudo usage, new members added to administrative groups, and processes spawning with elevated privileges unexpectedly. On Windows, Event ID 4672 (special privileges assigned) and 4728/4732 (group membership changes) are critical.

### 3. Lateral Movement

Track NTLM authentication across the network. If a single set of credentials is used to authenticate to multiple hosts in rapid succession, it likely indicates pass-the-hash or pass-the-ticket activity. Correlate with Sysmon Event ID 3 (network connections) for additional context.

### 4. Command-and-Control (C2) Beaconing

Statistical analysis of outbound network connections can reveal C2 beaconing. Look for connections at regular intervals to uncommon domains with consistent payload sizes.

```spl
index=proxy
| bin _time span=1m
| stats count by dest_ip, _time
| timechart span=1h stdev(count) as std_dev, avg(count) as avg_count by dest_ip
| where std_dev < 2 AND avg_count > 5
```

## Incident Response Workflow Integration

A SIEM is most effective when it feeds directly into an incident response workflow. The typical flow is:

1. **Alert Triggered** — SIEM rule fires and creates an alert.
2. **Triage** — SOC analyst reviews context, enriches with threat intelligence.
3. **Escalation** — High-severity alerts escalated to Tier 2 or the IR team.
4. **Containment** — Automated or manual isolation of affected systems.
5. **Investigation** — Deep-dive forensic analysis using raw logs.
6. **Remediation** — Patch, reconfigure, or rebuild affected assets.
7. **Documentation** — Record findings for compliance and lessons learned.

## SOAR Integration

### TheHive Integration

TheHive is an open-source security incident response platform that integrates tightly with Wazuh and Splunk.

```python
# Example: Wazuh active response script to create TheHive alert
import requests
import json
import sys

THEHIVE_URL = "https://thehive.internal:9000"
THEHIVE_API_KEY = "YOUR_API_KEY"

def create_alert(alert_data):
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    alert = {
        "title": f"Wazuh Alert: {alert_data['rule']['description']}",
        "description": json.dumps(alert_data, indent=2),
        "severity": min(alert_data['rule']['level'] // 4 + 1, 3),
        "type": "wazuh",
        "source": "Wazuh SIEM",
        "sourceRef": alert_data['id'],
        "tags": alert_data['rule'].get('groups', []),
        "tlp": 2,
        "pap": 2
    }
    
    response = requests.post(
        f"{THEHIVE_URL}/api/alert",
        headers=headers,
        json=alert,
        verify=False
    )
    return response.json()
```

### Shuffle SOAR Automation

Shuffle provides visual workflow automation. A typical playbook triggered by a SIEM alert:

1. **Receive alert** from Wazuh/Splunk webhook.
2. **Enrich** — Query VirusTotal, AbuseIPDB, and Shodan for IOC context.
3. **Decision** — If malicious, proceed to containment.
4. **Contain** — Block IP on firewall via API, isolate endpoint via EDR.
5. **Notify** — Send Slack/Teams message to the SOC channel.
6. **Document** — Create TheHive case with all enrichment data attached.

## Best Practices for SIEM Deployment

### Log Retention Policy

- **Hot Storage (0–30 days):** Active searching and correlation.
- **Warm Storage (30–90 days):** Slower queries but still indexed.
- **Cold Storage (90–365 days):** Compressed archives for compliance.
- **Frozen/Archive (1–7 years):** Regulatory compliance (PCI DSS, HIPAA).

### Alert Tuning

The number one cause of SOC analyst burnout is alert fatigue. Tune aggressively:

- Start with a small set of high-fidelity rules and expand gradually.
- Whitelist known-good activity (scheduled tasks, backup processes, monitoring tools).
- Use risk-based alerting — assign risk scores to events and alert on cumulative risk per entity rather than individual events.
- Review and refine rules monthly based on false positive rates.

### Deployment Checklist

- [ ] Deploy agents to all endpoints (servers, workstations, network devices).
- [ ] Normalize log formats across all sources.
- [ ] Configure log rotation and retention policies.
- [ ] Build baseline dashboards for authentication, network, and endpoint activity.
- [ ] Write and test detection rules mapped to MITRE ATT&CK.
- [ ] Integrate with ticketing and SOAR platforms.
- [ ] Conduct purple team exercises to validate detection coverage.
- [ ] Document runbooks for each high-severity alert.

## Final Thoughts

A SIEM is only as good as the people operating it and the rules they write. Deploying Wazuh or Splunk is the easy part — the real work is in continuous tuning, building detection coverage mapped to your threat model, and integrating response workflows that minimize time-to-containment. Start small, measure your detection coverage against MITRE ATT&CK, and iterate relentlessly. The attackers certainly do.
