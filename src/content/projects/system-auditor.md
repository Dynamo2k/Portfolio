---
title: "System-Auditor - Automated Security Checker"
description: "C-based tool for system security auditing and vulnerability scanning on Linux systems."
date: 2024-05-15
category: "Defensive Security"
tags: ["C", "Security", "System Programming", "Linux"]
github: "https://github.com/Dynamo2k1/System-Auditor"
stars: 4
featured: true
---

## Project Overview

System-Auditor performs comprehensive security assessments on Linux systems, checking configurations, permissions, and potential vulnerabilities against established security benchmarks.

### Key Features

- **Permission Auditing**: Check file and directory permissions for security issues
- **Service Analysis**: Identify running services and potential attack surfaces
- **Configuration Review**: Validate system configurations against CIS benchmarks
- **Network Analysis**: Scan for open ports and suspicious connections
- **Report Generation**: Detailed HTML reports with remediation recommendations

### Checks Performed

- SUID/SGID binary analysis
- World-writable file detection
- Password policy compliance
- Firewall configuration review
- Kernel parameter validation
