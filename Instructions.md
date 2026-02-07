# PORTFOLIO IMPROVEMENT - COMPREHENSIVE PHASED IMPLEMENTATION

**Current Portfolio:** https://portfolio-beta-three-tnc4w45u1l.vercel.app/  
**LinkedIn Profile:** https://www.linkedin.com/in/rana-uzair-ahmad-82b8b6223

---

## PHASE 1: UPDATE PERSONAL & PROFESSIONAL INFORMATION

### 1.1 Update Professional Title & Bio

**Current Status:** Listed as "SOC Analyst @ NCCS | Penetration Tester @ ZeroxInnovation"

**ACTION REQUIRED:**
Update based on LinkedIn profile to reflect current role:

```yaml
Updated Information:
  professional_title: "Cyber Security Engineer | Penetration Tester"
  current_role: "Cyber Security Engineer"
  primary_expertise: 
    - Penetration Testing
    - Security Engineering
    - Threat Analysis
  
  headline: "Cyber Security Engineer | Penetration Tester | Security Researcher"
  
  bio_summary: |
    Cyber Security Engineer specializing in penetration testing, vulnerability assessment,
    and security tool development. Passionate about offensive security, CTF competitions,
    and building innovative security solutions.
```

**Files to Update:**
- `src/pages/index.astro` - Hero section
- `src/pages/about.astro` - Professional bio
- `src/pages/resume.astro` - Resume header
- `src/components/Header.astro` - Site tagline
- `src/components/Footer.astro` - Footer bio

### 1.2 Update Experience Section

**Update the Professional Experience Timeline:**

```yaml
Current Experience:
  - title: "Cyber Security Engineer"
    company: "Current Role"
    period: "Recent - Present"
    description: |
      - Conduct comprehensive penetration testing and vulnerability assessments
      - Develop and maintain security tools for automated testing
      - Perform threat modeling and security architecture reviews
      - Lead red team operations and security awareness initiatives
    technologies:
      - Burp Suite, Metasploit, Nmap
      - Python, Bash, PowerShell
      - OWASP Top 10, MITRE ATT&CK
      
  - title: "Penetration Tester"
    company: "ZeroxInnovation"
    period: "April 2025 - Present"
    description: |
      - Execute penetration testing engagements for clients
      - Identify and exploit vulnerabilities in web applications and networks
      - Provide detailed security reports with remediation recommendations
    
  - title: "SOC Analyst"
    company: "National Center of Cyber Security"
    period: "[Date] - [Date]"
    description: |
      - Monitored security incidents using SIEM platforms (Wazuh, Splunk)
      - Developed custom detection rules and threat hunting queries
      - Analyzed threat patterns and conducted incident response
```

**Update Skills Section:**

```yaml
Primary Skills:
  Penetration Testing:
    - Web Application Security Testing
    - Network Penetration Testing
    - API Security Testing
    - Mobile Application Security
    - Wireless Security Assessment
    
  Security Engineering:
    - Secure Architecture Design
    - Security Tool Development
    - Automation & Scripting
    - CI/CD Security Integration
    
  Threat Analysis:
    - Threat Modeling
    - Malware Analysis
    - Vulnerability Research
    - Security Code Review
    
Tools & Technologies:
  Offensive:
    - Burp Suite Professional
    - Metasploit Framework
    - Nmap, Nessus, OpenVAS
    - SQLmap, OWASP ZAP
    - Cobalt Strike (Red Team)
    
  Programming:
    - Python (Advanced)
    - Bash/Shell Scripting
    - PowerShell
    - C/C++
    - JavaScript
```

---

## PHASE 2: FIX IMAGES & VISUAL CONTENT

### 2.1 Replace Profile/Main Image

**CURRENT ISSUE:** Profile image is incorrect/outdated

**SOLUTION:**
```
Option 1: Professional Photo
- Use a professional headshot
- Dark/matte black background preferred
- Dimensions: 500x500px minimum
- Format: WebP (with JPG fallback)
- Location: /public/images/profile/rana-uzair.webp

Option 2: Cybersecurity-Themed Avatar
- Use AI-generated cybersecurity professional avatar
- Consistent with brand colors (matte black + cyan-green)
- Modern, abstract representation
- Format: SVG or WebP

Recommended AI Image Prompt for Avatar:
"Professional cybersecurity engineer avatar, digital art style, matte black
background, neon cyan and green accents, circuit board patterns, shield symbol,
modern minimal design, high contrast, suitable for portfolio website"
```

**Files to Update:**
- `/public/images/profile/` - Add new profile image
- `src/pages/about.astro` - Update image path
- `src/components/Hero.astro` - Update hero image (if present)

### 2.2 Add Blog Post Images

**REQUIREMENT:** Each of the 10-15 new blogs needs relevant images

**IMAGE GENERATION STRATEGY:**

For each blog post, generate images using AI with these prompts:

```yaml
Blog Image Dimensions: 1200x630px (OG image size)
Format: WebP with JPG fallback
Location: /public/images/blog/[blog-slug].webp

Image Prompt Template:
"Cybersecurity illustration for [TOPIC], digital art, modern tech aesthetic,
matte black background, neon cyan and green highlights, circuit patterns,
abstract representation of [CONCEPT], professional, high quality"

Examples:

1. Zero Trust Architecture Blog:
   "Zero trust security architecture diagram, matte black background, neon
   cyan network nodes, green verification shields, abstract digital fortress,
   circuit board patterns, modern minimalist style"

2. Web Application Security Blog:
   "Web application security shield, SQL injection prevention, matte black
   background, neon green code snippets, cyan lock symbols, abstract security
   layers, digital protection concept"

3. Penetration Testing Blog:
   "Ethical hacking penetration testing, terminal commands, matte black screen,
   neon green text, cyan highlighting, security tools icons, abstract network
   map, professional cybersecurity aesthetic"
```

**Implementation:**
```javascript
// Add to each blog post frontmatter
---
image: "/images/blog/[slug].webp"
imageAlt: "Descriptive alt text for accessibility"
imagePrompt: "AI generation prompt for this image"
---
```

---

## PHASE 3: WRITE 10-15 COMPREHENSIVE CYBERSECURITY BLOG POSTS

### 3.1 Blog Post Structure Template

**Each blog should follow this structure:**

```markdown
---
title: "Blog Post Title"
description: "Clear 1-2 sentence description"
date: "YYYY-MM-DD"
category: "Tutorial | Analysis | Writeup | Guide | Opinion"
tags: ["tag1", "tag2", "tag3", "tag4"]
image: "/images/blog/slug.webp"
imageAlt: "Image description"
author: "Rana Uzair Ahmad"
readTime: "10-15 min"
difficulty: "Beginner | Intermediate | Advanced"
---

# Main Title

## Introduction
Brief introduction to the topic and what readers will learn.

## Table of Contents
- [Section 1](#section-1)
- [Section 2](#section-2)
- [Section 3](#section-3)

## Section 1: [Topic]
Detailed content with examples, code snippets, diagrams.

### Subsection 1.1
More detailed information.

```code
Code examples with syntax highlighting
```

## Section 2: [Practical Application]
Real-world examples and use cases.

## Section 3: [Advanced Topics]
Deep dive into complex concepts.

## Key Takeaways
- Bullet point summary
- Main lessons learned
- Action items

## Conclusion
Summary and next steps.

## References & Further Reading
- Link 1
- Link 2

---

**AI Image Generation Prompt for this Blog:**
```
[Detailed prompt for generating relevant cybersecurity image]
```
```

### 3.2 Blog Topics & Detailed Outlines

**BLOG 1: Zero Trust Architecture - A Practical Implementation Guide**

```yaml
Category: Security Architecture
Tags: Zero Trust, Network Security, Enterprise Security, Architecture
Difficulty: Intermediate
Read Time: 12 min

Outline:
  Introduction:
    - Definition of Zero Trust
    - Why traditional perimeter security fails
    - "Never trust, always verify" principle
    
  Section 1: Core Principles
    - Identity verification
    - Least privilege access
    - Micro-segmentation
    - Continuous monitoring
    
  Section 2: Implementation Strategy
    - Step 1: Identify your protect surface
    - Step 2: Map transaction flows
    - Step 3: Build Zero Trust architecture
    - Step 4: Create Zero Trust policy
    - Step 5: Monitor and maintain
    
  Section 3: Real-World Case Study
    - Implementation challenges
    - Solutions and workarounds
    - Lessons learned
    
  Tools & Technologies:
    - Okta / Azure AD for identity
    - Palo Alto / Zscaler for network
    - Crowdstrike for endpoints
    
  Conclusion:
    - Benefits of Zero Trust
    - Common pitfalls to avoid
    - Future of network security

AI Image Prompt:
"Zero trust architecture network diagram, matte black background, neon cyan
and green connections, identity verification shields, micro-segmentation zones,
continuous monitoring sensors, modern digital security illustration"
```

**BLOG 2: Advanced Web Application Penetration Testing Methodology**

```yaml
Category: Penetration Testing
Tags: Web Security, OWASP, Pentesting, Bug Bounty
Difficulty: Advanced
Read Time: 15 min

Outline:
  Introduction:
    - Evolution of web app security
    - Modern attack surfaces
    - Pentesting vs bug bounty hunting
    
  Section 1: Reconnaissance & Information Gathering
    - Passive reconnaissance (OSINT)
    - Active scanning techniques
    - Technology stack fingerprinting
    - Code examples with subfinder, amass
    
  Section 2: OWASP Top 10 Deep Dive
    - Injection attacks (SQL, NoSQL, Command)
      - Finding injection points
      - Exploitation techniques
      - Blind injection methods
    - Broken Authentication
      - Session hijacking
      - JWT vulnerabilities
      - OAuth misconfigurations
    - XSS (Stored, Reflected, DOM-based)
      - Bypassing WAF filters
      - Content Security Policy bypass
      - Stealing cookies & sessions
    
  Section 3: Advanced Techniques
    - Server-Side Request Forgery (SSRF)
    - XML External Entity (XXE)
    - Insecure Deserialization
    - Business Logic Vulnerabilities
    
  Section 4: Real Pentest Case Study
    - Initial reconnaissance findings
    - Vulnerability chain exploitation
    - Privilege escalation
    - Proof of concept
    
  Tools Showcase:
    - Burp Suite Professional techniques
    - Custom Python scripts for automation
    - ffuf for fuzzing
    - nuclei for vulnerability scanning
    
  Reporting:
    - Professional report structure
    - CVSS scoring
    - Remediation recommendations

AI Image Prompt:
"Web application penetration testing, security vulnerabilities diagram, OWASP
Top 10 icons, matte black background, neon green code injection, cyan security
shields, abstract web architecture, hacker terminal interface, modern cybersecurity art"
```

**BLOG 3: Building a Red Team Lab - From Beginner to Advanced**

```yaml
Category: Tutorial
Tags: Red Team, Home Lab, Pentesting, Practice
Difficulty: Beginner to Intermediate
Read Time: 14 min

Outline:
  Introduction:
    - What is a Red Team lab
    - Why you need one
    - Skills you'll develop
    
  Section 1: Lab Requirements & Planning
    - Hardware requirements (minimum & recommended)
    - Software requirements
    - Network topology design
    - Isolation and safety considerations
    
  Section 2: Building the Infrastructure
    - Hypervisor setup (VirtualBox, VMware, Proxmox)
    - Creating vulnerable VMs (DVWA, Metasploitable, HackTheBox)
    - Setting up Kali Linux attack machine
    - Windows AD environment setup
    
  Section 3: Offensive Tools Installation
    - Burp Suite configuration
    - Metasploit framework setup
    - Cobalt Strike (educational license)
    - Custom tool installation (AutoRecon, LinPEAS, WinPEAS)
    
  Section 4: Defensive Components
    - Deploying pfSense firewall
    - Setting up Wazuh SIEM
    - Windows Defender logs
    - Network traffic analysis with Wireshark
    
  Section 5: Practice Scenarios
    - Scenario 1: Web app exploitation
    - Scenario 2: Active Directory attack path
    - Scenario 3: Network pivoting
    - Scenario 4: Persistence mechanisms
    
  Section 6: Continuous Improvement
    - Adding new vulnerable machines
    - Creating custom challenges
    - Integrating CTF platforms
    
  Resources:
    - Free vulnerable machines
    - Learning platforms
    - Community forums

AI Image Prompt:
"Red team cybersecurity lab setup, virtual machines network topology, attack and
defense infrastructure, matte black background, neon green Kali Linux terminal,
cyan network connections, server racks illustration, modern tech aesthetic"
```

**BLOG 4: API Security Testing - Finding & Exploiting Vulnerabilities**

```yaml
Category: Security Testing
Tags: API Security, REST, GraphQL, Authentication, Authorization
Difficulty: Intermediate
Read Time: 12 min

Outline:
  Introduction:
    - Rise of API-first applications
    - Common API vulnerabilities
    - Why APIs are prime targets
    
  Section 1: API Security Fundamentals
    - REST vs GraphQL vs SOAP
    - Authentication mechanisms (OAuth2, JWT, API keys)
    - Authorization and access control
    
  Section 2: Reconnaissance
    - API endpoint discovery
    - Documentation analysis (Swagger, OpenAPI)
    - Identifying API versions
    - Technology fingerprinting
    
  Section 3: Common Vulnerabilities
    - Broken Object Level Authorization (BOLA)
      - Testing for IDOR
      - Exploitation examples
    - Broken Authentication
      - JWT manipulation
      - Token replay attacks
    - Excessive Data Exposure
    - Rate Limiting bypass
    - Mass Assignment
    
  Section 4: Testing Methodology
    - Manual testing with Burp Suite
    - Automated testing with Postman
    - API fuzzing techniques
    - GraphQL specific attacks (introspection, batching)
    
  Section 5: Real-World Examples
    - Case study: BOLA in ride-sharing app
    - Case study: JWT misconfiguration
    - Lessons learned from bug bounties
    
  Tools:
    - Burp Suite extensions
    - Postman collections
    - ffuf for API fuzzing
    - Custom Python scripts
    
  Best Practices:
    - Secure API design principles
    - Testing checklist
    - Remediation strategies

AI Image Prompt:
"API security testing illustration, REST endpoints diagram, authentication
tokens, matte black background, neon cyan API connections, green security
shields, JSON data flow, abstract network architecture, cybersecurity art"
```

**BLOG 5: Malware Analysis for Beginners - Static & Dynamic Techniques**

```yaml
Category: Malware Analysis
Tags: Malware, Reverse Engineering, Forensics, Analysis
Difficulty: Intermediate
Read Time: 16 min

Outline:
  Introduction:
    - What is malware analysis
    - Static vs Dynamic analysis
    - Safety precautions and lab setup
    
  Section 1: Setting Up Analysis Environment
    - Isolated VM setup
    - REMnux Linux distribution
    - Windows analysis VMs
    - Snapshot and rollback strategies
    
  Section 2: Static Analysis Techniques
    - File hashing and identification
    - String extraction
    - PE file analysis (headers, sections, imports)
    - Packing and obfuscation detection
    - Tools: PEStudio, DIE, strings, exiftool
    
  Section 3: Dynamic Analysis
    - Sandbox analysis (Any.Run, Joe Sandbox)
    - Process monitoring (Process Monitor, Process Hacker)
    - Network traffic analysis
    - Registry and file system changes
    - Tools: Wireshark, Regshot, Fakenet
    
  Section 4: Behavioral Analysis
    - C2 communication patterns
    - Persistence mechanisms
    - Privilege escalation attempts
    - Data exfiltration techniques
    
  Section 5: Disassembly and Debugging
    - Using IDA Pro / Ghidra
    - x64dbg for dynamic debugging
    - Identifying malicious functions
    - Deobfuscation techniques
    
  Section 6: Case Study
    - Analyzing a real-world malware sample
    - Step-by-step breakdown
    - IOC extraction
    - Writing analysis report
    
  Resources:
    - Malware samples sources (MalwareBazaar)
    - Analysis communities
    - Further learning

AI Image Prompt:
"Malware analysis laboratory, assembly code disassembly, debugger interface,
matte black background, neon green hexadecimal code, cyan analysis graphs,
virus specimen containment, digital forensics illustration, cybersecurity theme"
```

**BLOG 6: Cloud Security - Securing AWS, Azure, and GCP**

```yaml
Category: Cloud Security
Tags: AWS, Azure, GCP, Cloud Native, DevSecOps
Difficulty: Intermediate to Advanced
Read Time: 14 min

Outline:
  Introduction:
    - Cloud security challenges
    - Shared responsibility model
    - Multi-cloud considerations
    
  Section 1: AWS Security Best Practices
    - IAM roles and policies (least privilege)
    - S3 bucket security misconfigurations
    - Security groups and NACLs
    - CloudTrail and GuardDuty
    - Lambda security considerations
    
  Section 2: Azure Security
    - Azure AD and Conditional Access
    - Network Security Groups
    - Azure Key Vault
    - Azure Security Center
    - Storage account security
    
  Section 3: GCP Security
    - IAM and service accounts
    - VPC configurations
    - Cloud Armor (DDoS protection)
    - Security Command Center
    - GKE security
    
  Section 4: Common Cloud Vulnerabilities
    - Publicly exposed resources
    - Misconfigured IAM permissions
    - Unencrypted data
    - Credential exposure in code
    - SSRF to metadata endpoints
    
  Section 5: Cloud Security Tools
    - ScoutSuite for multi-cloud auditing
    - Prowler for AWS security
    - CloudSploit
    - Terraform security scanning
    
  Section 6: Secure IaC
    - Infrastructure as Code security
    - Policy as Code (Open Policy Agent)
    - CI/CD security integration
    
  Case Study:
    - Capital One breach analysis
    - Lessons learned
    - Prevention strategies

AI Image Prompt:
"Cloud security architecture, AWS Azure GCP logos, multi-cloud infrastructure,
matte black background, neon cyan cloud icons, green security shields, data
encryption, IAM access controls, modern cloud computing illustration"
```

**BLOG 7: Active Directory Attacks & Defense - A Complete Guide**

```yaml
Category: Windows Security
Tags: Active Directory, Red Team, Blue Team, Windows
Difficulty: Advanced
Read Time: 18 min

Outline:
  Introduction:
    - Active Directory in enterprise environments
    - Why AD is a prime target
    - Attack lifecycle overview
    
  Section 1: AD Enumeration
    - BloodHound for attack path analysis
    - PowerView and SharpView
    - LDAP enumeration
    - SMB shares and null sessions
    
  Section 2: Initial Access
    - Password spraying techniques
    - Kerberoasting
    - AS-REP roasting
    - LLMNR/NBT-NS poisoning with Responder
    
  Section 3: Lateral Movement
    - Pass-the-Hash attacks
    - Pass-the-Ticket
    - Overpass-the-Hash
    - PSExec, WMI, DCOM
    
  Section 4: Privilege Escalation
    - Token impersonation
    - DLL hijacking
    - Service account abuse
    - Misconfigured ACLs
    
  Section 5: Persistence
    - Golden Ticket
    - Silver Ticket
    - Skeleton Key
    - DCShadow
    
  Section 6: Defense Strategies
    - Tier model implementation
    - LAPS deployment
    - Privileged Access Workstations (PAWs)
    - Credential Guard
    - AppLocker and WDAC
    
  Section 7: Detection & Response
    - Event log monitoring
    - Sysmon configuration
    - Detecting Kerberos attacks
    - Honeypot accounts
    
  Tools Covered:
    - Offensive: BloodHound, Mimikatz, Rubeus, Impacket
    - Defensive: Microsoft ATA, Sysmon, Splunk queries
    
  Lab Exercise:
    - Setting up vulnerable AD lab
    - Attack demonstration
    - Detection implementation

AI Image Prompt:
"Active Directory network attack paths, BloodHound graph visualization, domain
controller, matte black background, neon green attack vectors, cyan defensive
shields, Kerberos tickets, Windows security illustration, enterprise network"
```

**BLOG 8: Bug Bounty Hunting - From Zero to First Bounty**

```yaml
Category: Bug Bounty
Tags: Bug Bounty, Web Security, Hacking, Recon
Difficulty: Beginner to Intermediate
Read Time: 13 min

Outline:
  Introduction:
    - What is bug bounty hunting
    - Platforms (HackerOne, Bugcrowd, Intigriti)
    - Realistic expectations and earnings
    
  Section 1: Getting Started
    - Creating profiles on platforms
    - Reading program policies
    - Understanding scope
    - Legal and ethical considerations
    
  Section 2: Reconnaissance Mastery
    - Subdomain enumeration (amass, subfinder, assetfinder)
    - Technology detection (Wappalyzer, BuiltWith)
    - Content discovery (dirsearch, ffuf, gobuster)
    - JavaScript analysis for secrets
    - GitHub dorking for exposed credentials
    
  Section 3: Common Bug Classes
    - XSS (where to look, how to exploit)
    - IDOR (finding and chaining)
    - SSRF (internal service access)
    - Open Redirect
    - CSRF
    - XXE
    
  Section 4: Methodology
    - Daily routine of a bug bounty hunter
    - Note-taking and organization
    - Testing workflow
    - Automation vs manual testing
    
  Section 5: Writing Reports
    - Report structure
    - Proof of concept creation
    - Impact assessment
    - Communication with security teams
    - Examples of good vs bad reports
    
  Section 6: First Bounty Strategy
    - Choosing the right program
    - Low-hanging fruits
    - Niche vulnerability types
    - Time management
    
  Section 7: Tools Arsenal
    - Essential tools list
    - Custom automation scripts
    - Browser extensions
    - Burp Suite configuration
    
  Success Stories:
    - Real bounties from my experience
    - Lessons learned
    - Common mistakes to avoid
    
  Resources:
    - Learning platforms
    - Twitter accounts to follow
    - Discord communities

AI Image Prompt:
"Bug bounty hunting platform interface, vulnerability reports, security researcher
at work, matte black background, neon green code snippets, cyan reward badges,
hacker terminal, web application security, modern cybersecurity illustration"
```

**BLOG 9: Network Security Monitoring with Wireshark & Zeek**

```yaml
Category: Network Security
Tags: Network Monitoring, Wireshark, Zeek, Traffic Analysis
Difficulty: Intermediate
Read Time: 12 min

Outline:
  Introduction:
    - Importance of network visibility
    - Wireshark vs Zeek (Bro)
    - Use cases for each tool
    
  Section 1: Wireshark Fundamentals
    - Capture filters vs display filters
    - Following TCP streams
    - Analyzing protocols (HTTP, DNS, TLS)
    - Detecting anomalies
    
  Section 2: Advanced Wireshark
    - Decrypting TLS traffic (with keys)
    - Extracting files from PCAP
    - Expert information analysis
    - Statistics and conversations
    - Custom color rules
    
  Section 3: Zeek (Bro) Introduction
    - Installation and setup
    - Log file structure
    - Zeek scripting basics
    - Integration with SIEM
    
  Section 4: Threat Hunting with Traffic Analysis
    - Detecting C2 communications
    - Identifying data exfiltration
    - Spotting port scans
    - DNS tunneling detection
    - Beaconing behavior
    
  Section 5: Case Studies
    - Analyzing malware traffic
    - Incident response with PCAP
    - APT detection patterns
    
  Section 6: Automation
    - Tshark for command-line analysis
    - Python with Scapy
    - Zeek scripting examples
    - Integration with detection systems
    
  Practical Exercises:
    - PCAP challenge walkthroughs
    - Building detection signatures
    
  Tools Mentioned:
    - Wireshark, Tshark
    - Zeek (Bro)
    - NetworkMiner
    - Moloch/Arkime

AI Image Prompt:
"Network traffic analysis, Wireshark packet capture interface, network topology
diagram, matte black background, neon green data packets, cyan network nodes,
protocol analysis, cybersecurity monitoring illustration, digital forensics"
```

**BLOG 10: Docker & Kubernetes Security - Container Hardening**

```yaml
Category: DevSecOps
Tags: Docker, Kubernetes, Container Security, DevSecOps
Difficulty: Advanced
Read Time: 15 min

Outline:
  Introduction:
    - Containerization security challenges
    - Attack surface of containers
    - Kubernetes complexity
    
  Section 1: Docker Security Best Practices
    - Image security (base images, scanning)
    - Dockerfile best practices
    - Secrets management (not in env vars!)
    - Runtime security
    - Resource limits
    - User namespaces
    
  Section 2: Container Image Scanning
    - Trivy, Clair, Anchore
    - CI/CD integration
    - Vulnerability prioritization
    - Image signing and verification
    
  Section 3: Kubernetes Security
    - RBAC configuration
    - Network policies
    - Pod Security Policies / Standards
    - Admission controllers
    - Secret management (Vault, Sealed Secrets)
    
  Section 4: Runtime Security
    - Falco for behavioral monitoring
    - Detecting container escapes
    - Syscall filtering
    - Audit logging
    
  Section 5: Common Vulnerabilities
    - Privileged containers
    - Host path mounts
    - Exposed Docker socket
    - Dirty COW and container escapes
    - Supply chain attacks
    
  Section 6: Secure CI/CD Pipeline
    - Image scanning in pipeline
    - Policy enforcement
    - Artifact signing
    - Deployment gating
    
  Section 7: Incident Response
    - Forensics in containers
    - Log aggregation
    - Detecting compromised containers
    
  Tools:
    - Docker Bench Security
    - kube-bench, kube-hunter
    - Falco
    - Trivy, Grype
    - Open Policy Agent
    
  Lab Demo:
    - Setting up secure K8s cluster
    - Implementing policies
    - Testing security controls

AI Image Prompt:
"Docker and Kubernetes container security, orchestration architecture, security
shields protecting containers, matte black background, neon cyan container pods,
green security policies, cloud native security, DevSecOps illustration"
```

**BLOG 11: SIEM Deployment & Threat Detection - Wazuh & Splunk**

```yaml
Category: SOC / SIEM
Tags: SIEM, Wazuh, Splunk, Threat Detection, SOC
Difficulty: Intermediate
Read Time: 14 min

Outline:
  Introduction:
    - What is SIEM
    - Wazuh vs Splunk comparison
    - When to use each
    
  Section 1: Wazuh Setup
    - Architecture (Manager, Agent, Indexer)
    - Installation on Linux
    - Agent deployment (Windows, Linux)
    - Filebeat configuration
    
  Section 2: Wazuh Detection Rules
    - Understanding rule syntax
    - Creating custom rules
    - Rule testing and validation
    - Common detection scenarios
    
  Section 3: Splunk Deployment
    - Splunk architecture
    - Forwarder configuration
    - Index management
    - User roles and access
    
  Section 4: Splunk Search Processing Language (SPL)
    - Basic searches
    - Statistical commands
    - Correlation searches
    - Creating dashboards
    
  Section 5: Threat Detection Use Cases
    - Brute force detection
    - Privilege escalation alerts
    - File integrity monitoring
    - Malware detection
    - Lateral movement
    
  Section 6: Incident Response
    - Alert triage workflow
    - Investigating events
    - Creating incident tickets
    - Playbook automation
    
  Section 7: Integration
    - SOAR integration (Shuffle, TheHive)
    - Threat intelligence feeds
    - Email alerting
    - Slack notifications
    
  Best Practices:
    - Log retention policies
    - Performance tuning
    - False positive reduction
    - Team workflows
    
  Real-World Scenarios:
    - Detecting ransomware
    - Identifying insider threats
    - Cloud infrastructure monitoring

AI Image Prompt:
"SIEM security operations center, Wazuh and Splunk dashboards, threat detection
alerts, matte black background, neon green log entries, cyan security graphs,
SOC analyst monitors, real-time threat intelligence, cybersecurity monitoring"
```

**BLOG 12: Mobile Application Security Testing (Android & iOS)**

```yaml
Category: Mobile Security
Tags: Android, iOS, Mobile App Security, Pentesting
Difficulty: Intermediate to Advanced
Read Time: 16 min

Outline:
  Introduction:
    - Mobile app security landscape
    - OWASP Mobile Top 10
    - Android vs iOS security models
    
  Section 1: Android Security Testing
    - Setting up test environment (Genymotion, Android Studio)
    - APK decompilation (apktool, jadx)
    - Static analysis (MobSF, QARK)
    - Dynamic analysis (Frida, Objection)
    
  Section 2: Common Android Vulnerabilities
    - Insecure data storage
    - Hardcoded secrets
    - Unprotected components
    - SSL pinning bypass
    - WebView vulnerabilities
    
  Section 3: iOS Security Testing
    - Jailbreak setup
    - IPA extraction and analysis
    - Cycript and Frida on iOS
    - Class-dump analysis
    
  Section 4: Common iOS Vulnerabilities
    - Keychain misuse
    - Plist file exposure
    - Binary protection bypass
    - Certificate pinning bypass
    
  Section 5: API Security in Mobile
    - Intercepting traffic (Burp, Charles Proxy)
    - Certificate pinning bypass
    - API authentication issues
    - Sensitive data in requests
    
  Section 6: Reverse Engineering
    - Smali code analysis
    - ARM assembly basics
    - Function hooking with Frida
    - Modifying app behavior
    
  Section 7: Automated Scanning
    - MobSF integration
    - CI/CD security scanning
    - Dependency checking
    
  Tools Arsenal:
    - apktool, jadx, dex2jar
    - Frida, Objection
    - Burp Suite Mobile Assistant
    - MobSF, QARK
    - Hopper, IDA Pro
    
  Real Examples:
    - Banking app vulnerabilities
    - Social media app security
    - Bug bounty findings
    
  Responsible Disclosure:
    - Reporting to vendors
    - Timeline expectations
    - Legal considerations

AI Image Prompt:
"Mobile application security testing, Android and iOS smartphones, code analysis
interface, matte black background, neon green app decompilation, cyan security
alerts, Frida hooking illustration, mobile pentesting, cybersecurity art"
```

**BLOG 13: Incident Response Playbook - Ransomware Attack**

```yaml
Category: Incident Response
Tags: Incident Response, Ransomware, Forensics, IR
Difficulty: Advanced
Read Time: 14 min

Outline:
  Introduction:
    - Ransomware threat landscape
    - Impact on organizations
    - Incident response framework (NIST, SANS)
    
  Section 1: Preparation Phase
    - Incident response team roles
    - Tools and resources pre-staging
    - Backup and recovery procedures
    - Contact lists and escalation
    
  Section 2: Detection & Analysis
    - Initial indicators of compromise
    - Ransomware behavior patterns
    - SIEM alert correlation
    - Scope determination
    
  Section 3: Containment
    - Immediate isolation steps
    - Network segmentation
    - Disabling accounts
    - Preserving evidence
    
  Section 4: Eradication
    - Identifying patient zero
    - Removing malware
    - Credential reset procedures
    - System hardening
    
  Section 5: Recovery
    - Restore from backups
    - Validation procedures
    - Staged restoration
    - Monitoring for re-infection
    
  Section 6: Lessons Learned
    - Post-incident review
    - Documentation requirements
    - Process improvements
    - Training needs
    
  Section 7: Forensic Analysis
    - Memory acquisition
    - Disk imaging
    - Log analysis
    - Timeline creation
    - IOC extraction
    
  Tools Used:
    - Volatility for memory forensics
    - FTK Imager for disk acquisition
    - Splunk for log analysis
    - KAPE for evidence collection
    
  Real Case Study:
    - Ransomware incident walkthrough
    - Decision points
    - Challenges faced
    - Outcomes
    
  Prevention:
    - Security controls to implement
    - User awareness training
    - Backup strategies

AI Image Prompt:
"Incident response ransomware attack, emergency response team, forensic analysis
screens, matte black background, neon red ransomware alert, cyan defensive
actions, digital forensics investigation, cybersecurity crisis management"
```

**BLOG 14: Secure Code Review - Finding Vulnerabilities in Source Code**

```yaml
Category: Application Security
Tags: Secure Coding, Code Review, SAST, AppSec
Difficulty: Advanced
Read Time: 15 min

Outline:
  Introduction:
    - Importance of secure code review
    - Shift-left security
    - Manual vs automated review
    
  Section 1: Code Review Methodology
    - Understanding the application
    - Data flow analysis
    - Identifying trust boundaries
    - Attack surface mapping
    
  Section 2: Common Vulnerability Patterns
    - SQL Injection in different languages
    - XSS prevention failures
    - Broken authentication
    - Insecure deserialization
    - Path traversal
    
  Section 3: Language-Specific Issues
    - Python: pickle, eval, exec dangers
    - JavaScript: prototype pollution, XXE
    - Java: XXE, deserialization
    - PHP: include vulnerabilities, type juggling
    - C/C++: buffer overflows, format strings
    
  Section 4: Framework Security
    - Django security misconfigurations
    - Spring Boot vulnerabilities
    - Express.js pitfalls
    - Rails security features
    
  Section 5: Cryptography Review
    - Weak algorithms
    - Hardcoded keys
    - Improper IV usage
    - Insecure random number generation
    
  Section 6: Authentication & Authorization
    - Session management issues
    - JWT vulnerabilities
    - OAuth implementation flaws
    - Privilege escalation
    
  Section 7: Automated Tools
    - SAST tools (SonarQube, Checkmarx, Semgrep)
    - Dependency scanning (Snyk, OWASP Dependency-Check)
    - Secret scanning (TruffleHog, GitLeaks)
    - IDE integration
    
  Section 8: Remediation
    - Secure coding guidelines
    - Fix verification
    - Developer training
    
  Case Studies:
    - Real vulnerabilities found
    - Exploitation scenarios
    - Proper fixes
    
  Checklist:
    - Code review checklist by language
    - OWASP ASVS alignment

AI Image Prompt:
"Secure code review, source code analysis, vulnerability detection, matte black
background, neon green code lines, cyan security highlights, bug detection,
SAST tools interface, application security, developer security illustration"
```

**BLOG 15: Career in Cybersecurity - From Student to Professional**

```yaml
Category: Career Guidance
Tags: Career, Cybersecurity, Learning Path, Certifications
Difficulty: Beginner
Read Time: 12 min

Outline:
  Introduction:
    - My journey into cybersecurity
    - Different career paths
    - Industry demand and opportunities
    
  Section 1: Getting Started
    - Required background knowledge
    - Free resources for beginners
    - Building home lab
    - CTF platforms for practice
    
  Section 2: Career Paths
    - Offensive Security (Pentester, Red Team)
    - Defensive Security (SOC, Blue Team)
    - Security Engineering
    - GRC (Governance, Risk, Compliance)
    - Security Research
    
  Section 3: Certifications Roadmap
    - Entry Level: CompTIA Security+, CEH
    - Intermediate: OSCP, GPEN, CySA+
    - Advanced: OSEP, OSCE, GXPN
    - Specialized: GCFA, GCIH, GWAPT
    
  Section 4: Building Portfolio
    - GitHub projects importance
    - Blog and writeups
    - Bug bounty achievements
    - Contributing to open source
    
  Section 5: Networking
    - Twitter community
    - LinkedIn presence
    - Conference attendance
    - Local security meetups
    
  Section 6: Job Search
    - Resume tips for cybersecurity
    - Interview preparation
    - Common interview questions
    - Salary negotiations
    
  Section 7: Continuous Learning
    - Staying updated with threats
    - Research and development
    - Teaching and mentoring
    
  My Experience:
    - Mistakes I made
    - What I wish I knew earlier
    - Recommendations for beginners
    
  Resources:
    - Learning platforms
    - YouTube channels
    - Podcasts
    - Books to read
    
  Conclusion:
    - Mindset for success
    - Long-term career planning
    - Work-life balance

AI Image Prompt:
"Cybersecurity career path journey, learning roadmap, certifications badges,
professional growth, matte black background, neon cyan career milestones, green
achievement icons, from beginner to expert, career guidance illustration"
```

### 3.3 AI Image Generation Prompts Summary

**For each blog, include at the end:**

```markdown
---

## AI Image Generation Prompt

Generate a professional cybersecurity illustration for this blog post using the following prompt:

```
[Specific AI image prompt for the blog topic]

Specifications:
- Dimensions: 1200x630px
- Format: PNG or WebP
- Style: Modern cybersecurity aesthetic
- Colors: Matte black background with neon cyan and green accents
- Theme: [Blog topic]
```

You can use this prompt with:
- DALL-E 3 (ChatGPT Plus)
- Midjourney
- Stable Diffusion
- Adobe Firefly
- Leonardo AI
```

---

## PHASE 4: FIX MOBILE RESPONSIVENESS

### 4.1 Current Issues

**IDENTIFIED PROBLEMS:**
- Text and components appear too large on mobile
- Layout doesn't scale properly
- Poor use of screen real estate
- Touch targets may be too small or large

### 4.2 Mobile Optimization Strategy

**Update `global.css` and component styles:**

```css
/* ========================================
   MOBILE RESPONSIVENESS FIXES
   ======================================== */

/* Base Mobile Styles (320px - 767px) */
@media (max-width: 767px) {
  /* Typography Scaling */
  html {
    font-size: 14px; /* Reduce base font size on mobile */
  }
  
  h1 {
    font-size: 2rem !important; /* Down from 3rem */
    line-height: 1.2;
  }
  
  h2 {
    font-size: 1.5rem !important; /* Down from 2.5rem */
  }
  
  h3 {
    font-size: 1.25rem !important;
  }
  
  p {
    font-size: 0.95rem;
    line-height: 1.6;
  }
  
  /* Container Padding */
  .container {
    padding: 1rem !important; /* Reduce from 2rem */
    max-width: 100%;
  }
  
  /* Hero Section */
  .hero {
    padding: 2rem 0 !important; /* Reduce from 4rem */
  }
  
  .hero h1 {
    font-size: 1.75rem !important;
    margin-bottom: 0.5rem;
  }
  
  .headline {
    font-size: 1.1rem !important;
    margin-bottom: 0.5rem;
  }
  
  .subheadline {
    font-size: 0.95rem !important;
    margin-bottom: 1rem;
  }
  
  /* CTA Buttons */
  .cta-buttons {
    flex-direction: column;
    width: 100%;
  }
  
  .btn-primary,
  .btn-secondary {
    width: 100%;
    padding: 0.75rem !important;
    font-size: 0.95rem !important;
  }
  
  /* Post Cards */
  .post-card {
    margin-bottom: 1.5rem;
  }
  
  .post-card img {
    height: 180px !important; /* Reduce from 200px */
  }
  
  .post-content {
    padding: 1.25rem !important;
  }
  
  .post-card h3 {
    font-size: 1.1rem !important;
    margin-bottom: 0.5rem;
  }
  
  .description {
    font-size: 0.9rem !important;
  }
  
  .tags {
    gap: 0.375rem !important;
  }
  
  .tag {
    font-size: 0.8rem !important;
    padding: 0.2rem 0.5rem !important;
  }
  
  /* Navigation */
  .header {
    padding: 1rem !important;
  }
  
  .header h1 {
    font-size: 1.25rem !important;
  }
  
  .header nav a {
    font-size: 0.9rem !important;
    padding: 0.5rem !important;
  }
  
  /* Sidebar - Stack on Mobile */
  .main-grid {
    grid-template-columns: 1fr !important;
  }
  
  .sidebar {
    order: -1; /* Show above main content */
    position: static !important;
  }
  
  .sidebar-section {
    padding: 1rem !important;
    margin-bottom: 1rem !important;
  }
  
  /* Blog Post Content */
  .blog-content {
    padding: 1.5rem 1rem !important;
  }
  
  .blog-content h2 {
    font-size: 1.5rem !important;
  }
  
  .blog-content h3 {
    font-size: 1.25rem !important;
  }
  
  .blog-content pre {
    padding: 0.75rem !important;
    font-size: 0.85rem !important;
    overflow-x: scroll;
  }
  
  .blog-content img {
    max-width: 100%;
    height: auto;
  }
  
  /* Footer */
  .footer {
    padding: 1.5rem 1rem !important;
  }
  
  .footer-grid {
    grid-template-columns: 1fr !important;
    gap: 1.5rem !important;
  }
}

/* Tablet Adjustments (768px - 1023px) */
@media (min-width: 768px) and (max-width: 1023px) {
  html {
    font-size: 15px;
  }
  
  .container {
    padding: 1.5rem;
  }
  
  .grid {
    grid-template-columns: repeat(2, 1fr) !important;
  }
  
  .main-grid {
    grid-template-columns: 1fr !important;
  }
}

/* Touch Target Improvements */
button,
a,
input,
.clickable {
  min-height: 44px; /* WCAG AA touch target size */
  min-width: 44px;
}

/* Prevent Horizontal Scroll */
body {
  overflow-x: hidden;
}

* {
  max-width: 100%;
}

pre {
  overflow-x: auto;
  max-width: 100%;
}
```

### 4.3 Component-Specific Mobile Fixes

**Update Header Component:**

```astro
---
// src/components/Header.astro
---

<header class="header">
  <div class="header-content">
    <div class="logo">
      <a href="/">
        <h1>Rana Uzair Ahmad</h1>
        <p class="tagline">Cyber Security Engineer</p>
      </a>
    </div>
    
    <!-- Mobile Menu Toggle -->
    <button class="mobile-menu-toggle" aria-label="Toggle menu">
      <span></span>
      <span></span>
      <span></span>
    </button>
    
    <!-- Desktop & Mobile Nav -->
    <nav class="nav" id="main-nav">
      <a href="/">Home</a>
      <a href="/blog/">Blog</a>
      <a href="/projects/">Projects</a>
      <a href="/ctf/">CTF</a>
      <a href="/about/">About</a>
      <a href="/resume/">Resume</a>
      <a href="/contact/">Contact</a>
      <a href="/Rana_Uzair_Ahmad_Resume.pdf" class="btn-resume" download>
        ↓ Resume
      </a>
    </nav>
  </div>
</header>

<style>
  .header {
    position: sticky;
    top: 0;
    background: rgba(13, 13, 13, 0.95);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border-subtle);
    z-index: 1000;
    padding: 1rem 2rem;
  }
  
  .header-content {
    max-width: 1400px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  
  .logo h1 {
    font-size: 1.5rem;
    margin: 0;
  }
  
  .tagline {
    font-size: 0.875rem;
    color: var(--accent-primary);
    margin: 0;
  }
  
  .mobile-menu-toggle {
    display: none;
    flex-direction: column;
    gap: 4px;
    background: none;
    border: none;
    padding: 0.5rem;
    cursor: pointer;
  }
  
  .mobile-menu-toggle span {
    width: 24px;
    height: 2px;
    background: var(--text-primary);
    transition: all 300ms ease;
  }
  
  .nav {
    display: flex;
    gap: 1.5rem;
    align-items: center;
  }
  
  .nav a {
    color: var(--text-primary);
    text-decoration: none;
    font-size: 0.95rem;
    transition: color 200ms ease;
  }
  
  .nav a:hover {
    color: var(--accent-primary);
  }
  
  .btn-resume {
    background: var(--accent-primary);
    color: #000;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-weight: 600;
  }
  
  /* Mobile Styles */
  @media (max-width: 768px) {
    .header {
      padding: 1rem;
    }
    
    .mobile-menu-toggle {
      display: flex;
    }
    
    .nav {
      position: fixed;
      top: 60px;
      right: -100%;
      width: 80%;
      max-width: 300px;
      height: calc(100vh - 60px);
      background: var(--bg-secondary);
      flex-direction: column;
      align-items: flex-start;
      padding: 2rem;
      transition: right 300ms ease;
      border-left: 1px solid var(--border-subtle);
    }
    
    .nav.active {
      right: 0;
    }
    
    .nav a {
      width: 100%;
      padding: 0.75rem 0;
      font-size: 1.1rem;
      border-bottom: 1px solid var(--border-subtle);
    }
    
    .btn-resume {
      width: 100%;
      text-align: center;
      margin-top: 1rem;
    }
  }
</style>

<script>
  const menuToggle = document.querySelector('.mobile-menu-toggle');
  const nav = document.querySelector('.nav');
  
  menuToggle?.addEventListener('click', () => {
    nav?.classList.toggle('active');
    menuToggle.classList.toggle('active');
  });
  
  // Close menu when clicking link
  nav?.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      nav.classList.remove('active');
      menuToggle?.classList.remove('active');
    });
  });
</script>
```

---

## PHASE 5: FIX BLOG LAYOUT SPACING

### 5.1 Current Issue

**PROBLEM:** Too much empty space on left and right sides in blog section

### 5.2 Solution

**Update Blog Post Layout:**

```astro
---
// src/layouts/BlogLayout.astro
const { frontmatter } = Astro.props;
---

<BaseLayout title={frontmatter.title}>
  <article class="blog-post">
    <header class="blog-header">
      <a href="/blog/" class="back-link">← Back to Blog</a>
      
      <div class="blog-meta">
        <span class="category">{frontmatter.category}</span>
        <time>{frontmatter.date}</time>
      </div>
      
      <h1>{frontmatter.title}</h1>
      <p class="blog-description">{frontmatter.description}</p>
      
      <div class="tags">
        {frontmatter.tags.map(tag => (
          <span class="tag">{tag}</span>
        ))}
      </div>
      
      {frontmatter.image && (
        <img 
          src={frontmatter.image} 
          alt={frontmatter.imageAlt || frontmatter.title} 
          class="featured-image"
        />
      )}
    </header>
    
    <div class="blog-content">
      <slot />
    </div>
    
    {frontmatter.imagePrompt && (
      <div class="ai-image-prompt">
        <h2>AI Image Generation Prompt</h2>
        <p>Generate an illustration for this blog using:</p>
        <pre><code>{frontmatter.imagePrompt}</code></pre>
        <p class="tools">Try: DALL-E 3, Midjourney, Stable Diffusion, or Leonardo AI</p>
      </div>
    )}
  </article>
</BaseLayout>

<style>
  .blog-post {
    max-width: 900px; /* Optimal reading width */
    margin: 0 auto;
    padding: 2rem;
  }
  
  .blog-header {
    margin-bottom: 3rem;
  }
  
  .back-link {
    display: inline-block;
    color: var(--text-secondary);
    margin-bottom: 1rem;
    transition: color 200ms ease;
  }
  
  .back-link:hover {
    color: var(--accent-primary);
  }
  
  .blog-meta {
    display: flex;
    gap: 1rem;
    align-items: center;
    margin-bottom: 1rem;
  }
  
  .category {
    background: var(--accent-primary);
    color: #000;
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 600;
  }
  
  time {
    color: var(--text-secondary);
    font-size: 0.95rem;
  }
  
  .blog-header h1 {
    font-size: 2.5rem;
    margin: 1rem 0;
    line-height: 1.2;
  }
  
  .blog-description {
    font-size: 1.125rem;
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
  }
  
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 2rem;
  }
  
  .tag {
    background: var(--bg-elevated);
    color: var(--text-secondary);
    padding: 0.375rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
  }
  
  .featured-image {
    width: 100%;
    height: auto;
    max-height: 500px;
    object-fit: cover;
    border-radius: 12px;
    margin-top: 2rem;
  }
  
  .blog-content {
    font-size: 1.0625rem;
    line-height: 1.75;
    color: var(--text-primary);
  }
  
  /* Content Spacing */
  .blog-content h2 {
    font-size: 2rem;
    margin: 3rem 0 1.5rem;
    border-bottom: 2px solid var(--border-subtle);
    padding-bottom: 0.5rem;
  }
  
  .blog-content h3 {
    font-size: 1.5rem;
    margin: 2.5rem 0 1rem;
  }
  
  .blog-content p {
    margin-bottom: 1.5rem;
  }
  
  .blog-content ul,
  .blog-content ol {
    margin: 1.5rem 0;
    padding-left: 2rem;
  }
  
  .blog-content li {
    margin-bottom: 0.75rem;
  }
  
  .blog-content pre {
    background: #1e1e1e;
    padding: 1.5rem;
    border-radius: 8px;
    overflow-x: auto;
    margin: 2rem 0;
    border: 1px solid var(--border-subtle);
  }
  
  .blog-content code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.925em;
  }
  
  .blog-content :not(pre) > code {
    background: var(--bg-elevated);
    color: var(--accent-primary);
    padding: 0.2em 0.4em;
    border-radius: 4px;
  }
  
  .blog-content img {
    max-width: 100%;
    height: auto;
    border-radius: 8px;
    margin: 2rem 0;
  }
  
  .blog-content blockquote {
    border-left: 4px solid var(--accent-primary);
    padding-left: 1.5rem;
    margin: 2rem 0;
    font-style: italic;
    color: var(--text-secondary);
  }
  
  .ai-image-prompt {
    margin-top: 4rem;
    padding: 2rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-medium);
    border-radius: 12px;
  }
  
  .ai-image-prompt h2 {
    font-size: 1.5rem;
    margin-bottom: 1rem;
  }
  
  .ai-image-prompt pre {
    background: var(--bg-primary);
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
  }
  
  .tools {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-top: 1rem;
  }
  
  /* Mobile Responsive */
  @media (max-width: 768px) {
    .blog-post {
      padding: 1rem;
    }
    
    .blog-header h1 {
      font-size: 1.75rem;
    }
    
    .blog-description {
      font-size: 1rem;
    }
    
    .blog-content {
      font-size: 1rem;
    }
    
    .blog-content h2 {
      font-size: 1.5rem;
      margin: 2rem 0 1rem;
    }
    
    .blog-content h3 {
      font-size: 1.25rem;
    }
    
    .blog-content pre {
      padding: 1rem;
      font-size: 0.875rem;
    }
  }
</style>
```

**Key Improvements:**
- Max-width: 900px (optimal reading width)
- Centered content with auto margins
- Proper spacing on mobile
- No excessive empty space
- Better typography hierarchy

---

## PHASE 6: ADD THEME SWITCHING

### 6.1 Theme Options

**Implement 3 themes:**
1. Matte Black (default)
2. Jet Black
3. Light/White

### 6.2 Implementation

**Create Theme System:**

```typescript
// src/utils/themes.ts

export const themes = {
  matte: {
    name: 'Matte Black',
    colors: {
      'bg-primary': '#0d0d0d',
      'bg-secondary': '#1a1a1a',
      'bg-elevated': '#262626',
      'bg-hover': '#303030',
      'accent-primary': '#00ff9f',
      'accent-secondary': '#00d4ff',
      'text-primary': '#e8e8e8',
      'text-secondary': '#a0a0a0',
      'border-subtle': '#2a2a2a',
    }
  },
  jet: {
    name: 'Jet Black',
    colors: {
      'bg-primary': '#000000',
      'bg-secondary': '#0a0a0a',
      'bg-elevated': '#1a1a1a',
      'bg-hover': '#242424',
      'accent-primary': '#00ff9f',
      'accent-secondary': '#00d4ff',
      'text-primary': '#ffffff',
      'text-secondary': '#b0b0b0',
      'border-subtle': '#1f1f1f',
    }
  },
  light: {
    name: 'Light Mode',
    colors: {
      'bg-primary': '#ffffff',
      'bg-secondary': '#f5f5f5',
      'bg-elevated': '#e8e8e8',
      'bg-hover': '#d0d0d0',
      'accent-primary': '#00b386',
      'accent-secondary': '#0096cc',
      'text-primary': '#1a1a1a',
      'text-secondary': '#4a4a4a',
      'border-subtle': '#e0e0e0',
    }
  }
};

export function applyTheme(themeName: keyof typeof themes) {
  const theme = themes[themeName];
  const root = document.documentElement;
  
  Object.entries(theme.colors).forEach(([key, value]) => {
    root.style.setProperty(`--${key}`, value);
  });
  
  localStorage.setItem('theme', themeName);
}

export function getTheme(): keyof typeof themes {
  const saved = localStorage.getItem('theme');
  return (saved as keyof typeof themes) || 'matte';
}
```

**Create Theme Switcher Component:**

```astro
---
// src/components/ThemeSwitcher.astro
---

<div class="theme-switcher">
  <button class="theme-btn" data-theme="matte" title="Matte Black">
    <span class="theme-preview matte"></span>
  </button>
  <button class="theme-btn" data-theme="jet" title="Jet Black">
    <span class="theme-preview jet"></span>
  </button>
  <button class="theme-btn" data-theme="light" title="Light Mode">
    <span class="theme-preview light"></span>
  </button>
</div>

<style>
  .theme-switcher {
    display: flex;
    gap: 0.5rem;
    padding: 0.5rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
  }
  
  .theme-btn {
    background: none;
    border: 2px solid transparent;
    border-radius: 6px;
    padding: 4px;
    cursor: pointer;
    transition: all 200ms ease;
  }
  
  .theme-btn:hover {
    border-color: var(--accent-primary);
  }
  
  .theme-btn.active {
    border-color: var(--accent-primary);
    background: var(--bg-elevated);
  }
  
  .theme-preview {
    display: block;
    width: 32px;
    height: 32px;
    border-radius: 4px;
  }
  
  .theme-preview.matte {
    background: linear-gradient(135deg, #0d0d0d 0%, #1a1a1a 100%);
    border: 1px solid #00ff9f;
  }
  
  .theme-preview.jet {
    background: linear-gradient(135deg, #000000 0%, #0a0a0a 100%);
    border: 1px solid #00ff9f;
  }
  
  .theme-preview.light {
    background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
    border: 1px solid #00b386;
  }
</style>

<script>
  import { applyTheme, getTheme } from '../utils/themes';
  
  // Apply saved theme on load
  const currentTheme = getTheme();
  applyTheme(currentTheme);
  
  // Set active button
  document.querySelector(`[data-theme="${currentTheme}"]`)?.classList.add('active');
  
  // Theme switcher
  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const theme = btn.getAttribute('data-theme') as 'matte' | 'jet' | 'light';
      applyTheme(theme);
      
      // Update active state
      document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });
</script>
```

**Add to Header:**

```astro
<!-- In Header.astro -->
<div class="header-actions">
  <ThemeSwitcher />
  <a href="/Rana_Uzair_Ahmad_Resume.pdf" class="btn-resume" download>
    ↓ Resume
  </a>
</div>
```

---

## PHASE 7: FINAL CHECKLIST & QUALITY ASSURANCE

### 7.1 Content Verification

- [ ] Personal information updated (Cyber Security Engineer)
- [ ] LinkedIn information synchronized
- [ ] All 10-15 blogs written and published
- [ ] Each blog has AI image generation prompt
- [ ] Profile/main image replaced
- [ ] Blog post images added

### 7.2 Design Verification

- [ ] Matte black theme applied
- [ ] Mobile responsive (test on real devices)
- [ ] Blog spacing fixed (no excessive whitespace)
- [ ] Theme switcher working (3 themes)
- [ ] All images optimized
- [ ] Typography readable on all themes

### 7.3 Technical Verification

- [ ] All links working
- [ ] Resume download functional
- [ ] Navigation smooth
- [ ] Mobile menu working
- [ ] No console errors
- [ ] Fast page load (< 3s)
- [ ] Lighthouse scores: 90+

### 7.4 Cross-Browser Testing

- [ ] Chrome/Edge (Chromium)
- [ ] Firefox
- [ ] Safari (desktop & mobile)
- [ ] Mobile browsers (Chrome, Safari)

### 7.5 Accessibility

- [ ] Keyboard navigation works
- [ ] Screen reader friendly
- [ ] Color contrast WCAG AA
- [ ] Alt text on all images
- [ ] Focus indicators visible

---

## PHASE 8: DEPLOYMENT & MONITORING

### 8.1 Pre-Deployment

```bash
# Build and test locally
npm run build
npm run preview

# Check for errors
npm run check

# Test on different devices
# Use Chrome DevTools device emulator
```

### 8.2 Deployment to Vercel

```bash
# Push to GitHub
git add .
git commit -m "feat: major portfolio update - new blogs, themes, mobile fixes"
git push origin main

# Vercel auto-deploys from GitHub
# Or manual deploy:
vercel --prod
```

### 8.3 Post-Deployment Verification

- [ ] Visit live URL
- [ ] Test all pages
- [ ] Verify images load
- [ ] Check mobile experience
- [ ] Test theme switching
- [ ] Download resume works
- [ ] All blog links work
- [ ] Share on social media (test OG images)

---

## SUCCESS METRICS

**Portfolio should achieve:**
- ✅ Professional Cyber Security Engineer positioning
- ✅ 10-15 high-quality, comprehensive blog posts
- ✅ Perfect mobile responsiveness
- ✅ Clean, balanced blog layout (no excessive spacing)
- ✅ 3 working themes (Matte Black, Jet Black, Light)
- ✅ Fast loading (< 3s)
- ✅ 90+ Lighthouse scores
- ✅ Modern, professional appearance
- ✅ All images AI-generated with prompts provided

---

## TIMELINE ESTIMATE

**Phase 1:** Update Information - 1 hour  
**Phase 2:** Fix Images - 2 hours  
**Phase 3:** Write 10-15 Blogs - 12-15 hours  
**Phase 4:** Mobile Fixes - 3 hours  
**Phase 5:** Blog Layout - 2 hours  
**Phase 6:** Theme Switching - 3 hours  
**Phase 7:** QA Testing - 2 hours  
**Phase 8:** Deployment - 1 hour  

**Total:** ~26-30 hours

---

## NOTES & RECOMMENDATIONS

1. **Blog Writing:** Focus on quality over quantity. Better to have 10 excellent posts than 15 mediocre ones.

2. **Images:** Generate all AI images using consistent style (matte black background, neon cyan/green accents).

3. **Mobile Testing:** Test on real devices, not just emulators.

4. **Theme Persistence:** Themes save to localStorage, persist across sessions.

5. **SEO:** Each blog should have unique meta title and description.

6. **Social Sharing:** Generate OG images for each blog (1200x630px).

7. **Future Content:** Plan to add 1-2 new blogs per month to keep portfolio fresh.

8. **Analytics:** Consider adding Google Analytics or Plausible to track visits.

---

## COMPLETION CRITERIA

Portfolio is complete when:
1. All 8 phases are checked off
2. Live deployment is successful
3. Mobile experience is smooth
4. All 10-15 blogs are published
5. Themes work correctly
6. No critical bugs
7. Personal information reflects current role
8. Professional appearance achieved

---

**END OF PHASED IMPLEMENTATION GUIDE**
