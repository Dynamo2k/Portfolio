---
title: "Incident Response Playbook - Ransomware Attack"
description: "Step-by-step incident response playbook for handling ransomware attacks, covering detection, containment, eradication, recovery, and forensic analysis."
date: "2025-06-15"
category: "Incident Response"
tags: ["Incident Response", "Ransomware", "Forensics", "IR"]
image: "/images/blog/incident-response-ransomware.webp"
imageAlt: "Incident response ransomware attack emergency response"
imagePrompt: "Incident response ransomware attack, emergency response team, forensic analysis screens, matte black background, neon red ransomware alert, cyan defensive actions, digital forensics investigation, cybersecurity crisis management"
author: "Rana Uzair Ahmad"
readTime: "14 min"
difficulty: "Advanced"
---

Ransomware is the most financially devastating cyber threat facing organizations today. A single incident can cripple operations for weeks, cost millions in recovery, and permanently damage trust. The difference between a controlled incident and a catastrophe comes down to one thing: preparation. This playbook walks through every phase of a ransomware incident response, from the moment an alert fires to the post-incident review that prevents it from happening again.

## Incident Response Frameworks

Two frameworks dominate the IR landscape. Both describe essentially the same process, organized differently.

**NIST SP 800-61 (4 Phases):**

1. Preparation
2. Detection & Analysis
3. Containment, Eradication & Recovery
4. Post-Incident Activity

**SANS Incident Response (6 Steps):**

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

I structure this playbook around the NIST framework but break out each sub-phase for clarity. In practice, these phases overlap — you may be containing on one segment of the network while still detecting spread on another.

## Phase 1: Preparation

Preparation is everything you do *before* the attack. When ransomware hits, there is no time to figure out who to call, where the backups are, or how to isolate a network segment.

### Incident Response Team Roles

| Role | Responsibility |
|------|---------------|
| **IR Lead** | Coordinates all response activities, makes escalation decisions |
| **Forensic Analyst** | Evidence collection, memory/disk analysis, timeline reconstruction |
| **SOC Analyst** | Monitoring, triage, SIEM correlation, IOC hunting |
| **Network Engineer** | Network isolation, firewall rules, traffic capture |
| **Sysadmin** | System restoration, backup verification, patching |
| **Legal/Compliance** | Regulatory notifications, law enforcement liaison |
| **Communications** | Internal/external messaging, executive briefings |

### Pre-Staged Tools (Go-Bag)

Every IR team should have a forensic toolkit ready to deploy at a moment's notice:

```
IR Go-Bag (Digital & Physical):
├── Forensic Workstation (SIFT, REMnux, or Kali)
├── Write-blockers (Tableau, CRU)
├── External drives (sanitized, encrypted)
├── Network tap / packet capture device
├── USB drives with:
│   ├── Volatility3
│   ├── KAPE (Kroll Artifact Parser and Extractor)
│   ├── Velociraptor agent
│   ├── Sysinternals Suite
│   ├── CyLR (live response collector)
│   └── FTK Imager
├── Chain of custody forms
└── Contact list (CISO, legal, insurance, FBI/CISA)
```

### Backup Validation

Your backups are your lifeline. Validate them *before* you need them:

- **3-2-1 Rule:** 3 copies, 2 different media types, 1 offsite/offline.
- Test restoration monthly on isolated systems.
- Ensure backups are air-gapped or immutable (e.g., AWS S3 Object Lock, Veeam immutable repositories).
- Document Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) for every critical system.

## Phase 2: Detection & Analysis

### Ransomware Indicators of Compromise (IOCs)

Ransomware typically exhibits several detectable behaviors before encryption begins:

**Pre-Encryption Indicators:**

- Mass file enumeration (thousands of file reads in seconds).
- Shadow copy deletion: `vssadmin delete shadows /all /quiet`.
- Disabling Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`.
- Reconnaissance commands: `whoami`, `net group "Domain Admins"`, `nltest /dclist:`.
- Lateral movement via PsExec, WMI, or RDP.
- Data staging in unusual directories before exfiltration (double extortion).

**Active Encryption Indicators:**

- File extension changes (`.encrypted`, `.locked`, `.ryuk`, `.conti`).
- Ransom note files (`README.txt`, `DECRYPT-FILES.html`).
- High CPU utilization across multiple hosts simultaneously.
- Unusual SMB traffic patterns (mass file writes to network shares).

### SIEM Correlation Rules

```xml
<!-- Wazuh rule: Detect shadow copy deletion -->
<rule id="100100" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine">vssadmin.*delete.*shadows</field>
  <description>CRITICAL: Volume Shadow Copy deletion detected — possible ransomware</description>
  <mitre>
    <id>T1490</id>
  </mitre>
  <group>ransomware,</group>
</rule>

<!-- Wazuh rule: Mass file rename (encryption indicator) -->
<rule id="100101" level="12" frequency="50" timeframe="30">
  <if_sid>61613</if_sid>
  <description>Mass file modification detected — possible ransomware encryption</description>
  <mitre>
    <id>T1486</id>
  </mitre>
  <group>ransomware,</group>
</rule>
```

```spl
# Splunk: Detect ransomware pre-encryption behavior
index=wineventlog (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
  (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*"
   OR CommandLine="*bcdedit*/set*recoveryenabled*no*"
   OR CommandLine="*wbadmin*delete*catalog*")
| stats count by Computer, User, CommandLine, _time
| sort -_time
```

### Ransomware Behavior Pattern Analysis

When you suspect ransomware, ask these questions immediately:

1. **What systems are affected?** Check SIEM for encryption indicators across all endpoints.
2. **Is it still spreading?** Monitor for new file modifications and lateral movement.
3. **What variant is it?** Upload a sample to ID Ransomware (id-ransomware.malwarehunterteam.com) or check the ransom note.
4. **Is there a decryptor available?** Check No More Ransom (nomoreransom.org).
5. **Has data been exfiltrated?** Check for large outbound data transfers (double extortion).

## Phase 3: Containment

Containment must be fast and decisive. Every minute the ransomware runs, more data is encrypted or exfiltrated.

### Immediate Actions (First 30 Minutes)

```bash
# 1. Network Isolation — block lateral movement
# On network firewall/switch, isolate affected VLAN
iptables -I FORWARD -s 10.0.5.0/24 -j DROP   # Block affected subnet
iptables -I FORWARD -d 10.0.5.0/24 -j DROP

# 2. Disable compromised accounts
net user compromised_account /active:no /domain
# Or in PowerShell:
Disable-ADAccount -Identity "compromised_user"

# 3. Block known malicious IPs/domains at perimeter
# Add to firewall blocklist, DNS sinkhole, or proxy deny list

# 4. Isolate infected endpoints (but do NOT power off — preserve memory)
# Use EDR isolation feature (CrowdStrike, SentinelOne, Defender for Endpoint)
```

**Critical: Do NOT power off infected systems.** Powering off destroys volatile memory that contains encryption keys, running processes, network connections, and other forensic evidence. Instead, isolate at the network level.

### Network Segmentation

```
Pre-Incident Network:
┌─────────────────────────────────────────┐
│  Flat Network (10.0.0.0/16)             │
│  Servers + Workstations + IoT           │
│  ← Ransomware spreads freely            │
└─────────────────────────────────────────┘

During Containment:
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Clean     │  │ Unknown  │  │ Infected │
│ Segment   │  │ (Triage) │  │ (Isolate)│
│ 10.0.1/24 │  │ 10.0.2/24│  │ 10.0.5/24│
└──────────┘  └──────────┘  └──────────┘
     ↕              ↕              ✗
  Monitored     Restricted     No Access
```

## Phase 4: Eradication

### Finding Patient Zero

The patient zero system is where the initial compromise occurred. Finding it is critical to understanding how the attacker got in and ensuring the access vector is closed.

```bash
# Analyze timeline using filesystem metadata
# Sort by earliest encryption timestamp
find /mnt/evidence -name "*.encrypted" -printf "%T+ %p\n" | sort | head -20

# Check Windows Event Logs for initial access
# Event ID 4624 (logon), 4625 (failed logon), 4688 (process creation)
# Look for the earliest suspicious activity

# Check email logs for phishing delivery
grep -r "\.zip\|\.iso\|\.lnk\|macro" /var/log/mail* | sort
```

### Credential Reset

Assume all credentials are compromised. Reset systematically:

1. **KRBTGT account** — Reset twice (with 12-hour gap) to invalidate all Kerberos tickets.
2. **All domain admin accounts** — New passwords, review membership.
3. **Service accounts** — Especially those with high privileges.
4. **Local administrator passwords** — Deploy LAPS (Local Administrator Password Solution).
5. **VPN and remote access credentials** — Force re-enrollment with MFA.

```powershell
# Reset KRBTGT password (run twice, 12 hours apart)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString "NewComplexPassword!" -AsPlainText -Force)

# Force password reset for all domain users
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true

# Disable accounts not used in 90+ days
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $threshold -and Enabled -eq $true} |
    Disable-ADAccount
```

## Phase 5: Recovery

### Staged Restoration Process

Do not restore everything at once. Prioritize and verify:

**Tier 1 — Critical Infrastructure (0–24 hours):**
- Active Directory domain controllers
- DNS and DHCP servers
- Core network infrastructure
- Communication systems (email, Teams)

**Tier 2 — Business Critical (24–72 hours):**
- Database servers
- Application servers
- File servers (from clean backups)

**Tier 3 — Standard Operations (72+ hours):**
- Workstations (reimage from gold image)
- Print servers, secondary services

```bash
# Verify backup integrity before restoration
sha256sum backup-archive-2025-06-14.tar.gz
# Compare against known-good checksum from backup log

# Mount backup read-only for inspection
mount -o ro,loop backup-image.img /mnt/backup-verify/

# Scan restored systems before reconnecting to network
clamscan -r /mnt/restored-system/
yara -r ransomware_rules.yar /mnt/restored-system/
```

## Phase 6: Forensic Analysis

### Memory Forensics with Volatility

Memory analysis can reveal encryption keys, running malware processes, and network connections that disk forensics cannot.

```bash
# Capture memory from live system (before isolation if possible)
# Using WinPMEM:
winpmem_mini_x64.exe memory.raw

# Identify OS profile
vol3 -f memory.raw windows.info

# List running processes — look for suspicious names
vol3 -f memory.raw windows.pslist
vol3 -f memory.raw windows.pstree

# Find hidden/terminated processes
vol3 -f memory.raw windows.psscan

# Check network connections — identify C2 communication
vol3 -f memory.raw windows.netscan | grep -i "ESTABLISHED\|SYN_SENT"

# Extract command line arguments — see what was executed
vol3 -f memory.raw windows.cmdline

# Dump suspicious process memory for malware analysis
vol3 -f memory.raw windows.memmap --pid 4892 --dump

# Check for injected code in processes
vol3 -f memory.raw windows.malfind

# Extract registry hives for credential analysis
vol3 -f memory.raw windows.registry.hivelist
vol3 -f memory.raw windows.hashdump
```

### Disk Forensics with FTK and Autopsy

```bash
# Create forensic disk image (do NOT work on original)
dc3dd if=/dev/sda of=evidence.dd hash=sha256 log=imaging.log

# Mount image read-only
mount -o ro,noexec,nosuid evidence.dd /mnt/evidence/

# Timeline analysis with plaso/log2timeline
log2timeline.py timeline.plaso /mnt/evidence/
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Search for ransomware artifacts
find /mnt/evidence -name "*.encrypted" -o -name "README*ransom*" -o -name "DECRYPT*"
find /mnt/evidence -newer /mnt/evidence/Windows/System32/config/SAM -name "*.exe"

# Check prefetch for execution history
ls /mnt/evidence/Windows/Prefetch/ | sort -t- -k2 | tail -20

# Analyze Windows Event Logs
evtx_dump.py /mnt/evidence/Windows/System32/winevt/Logs/Security.evtx | \
    grep -E "4624|4625|4688|4697|7045" > security_events.txt
```

### Building the Timeline

A comprehensive timeline is the most valuable forensic artifact. It tells the story of the entire attack:

```
[Timeline Example]
2025-06-14 02:14:33  Phishing email received (user: jsmith@corp.com)
2025-06-14 02:16:01  Malicious attachment opened (invoice.xlsm)
2025-06-14 02:16:05  PowerShell download cradle executed
2025-06-14 02:16:12  Cobalt Strike beacon established (C2: 185.x.x.x)
2025-06-14 02:30:00  Reconnaissance (whoami, net group, nltest)
2025-06-14 03:15:22  Mimikatz — credential harvesting
2025-06-14 03:45:00  Lateral movement via PsExec to DC01
2025-06-14 04:00:00  Domain Admin compromise
2025-06-14 04:30:00  Data exfiltration (200GB to external FTP)
2025-06-14 05:00:00  Shadow copies deleted on all systems
2025-06-14 05:01:00  Ransomware deployed via Group Policy
2025-06-14 05:01:30  Encryption begins across domain
2025-06-14 05:15:00  SOC alert — mass file modification detected
2025-06-14 05:18:00  IR team activated
```

## Prevention Strategies

### Technical Controls

- **Immutable backups** — Air-gapped or using object lock storage.
- **Network segmentation** — Limit blast radius of any single compromise.
- **Endpoint Detection and Response (EDR)** — CrowdStrike, SentinelOne, or Defender for Endpoint.
- **Email security** — Advanced threat protection, sandboxing attachments.
- **Patch management** — Prioritize known exploited vulnerabilities (CISA KEV catalog).
- **Privileged Access Management** — Just-in-time admin access, no standing privileges.
- **MFA everywhere** — VPN, email, cloud services, admin portals.

### Operational Controls

- **Tabletop exercises** — Simulate ransomware scenarios quarterly with all stakeholders.
- **Security awareness training** — Phishing simulations, social engineering awareness.
- **Incident response retainers** — Pre-negotiate with an IR firm (CrowdStrike, Mandiant, Secureworks).
- **Cyber insurance** — Understand your policy's coverage and notification requirements.

## Lessons Learned Template

After every incident, conduct a blameless post-mortem:

1. **What happened?** — Factual timeline of the incident.
2. **How was it detected?** — What alert or observation triggered the response?
3. **What went well?** — Effective containment, team coordination, tool effectiveness.
4. **What could be improved?** — Gaps in detection, slow response areas, missing tools.
5. **Action items** — Specific, assigned, and time-bound improvements.
6. **Metrics** — Time to detect, time to contain, time to recover, data loss scope.

## Final Thoughts

Ransomware incidents are chaotic, high-pressure events. The organizations that survive them are not the ones with the biggest budgets — they are the ones that prepared. Build your playbook before you need it. Test your backups. Run tabletop exercises. Pre-stage your forensic tools. When ransomware hits at 3 AM on a Saturday, you will be grateful for every minute you spent preparing.
