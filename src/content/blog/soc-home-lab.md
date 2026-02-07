---
title: "Building a Professional SOC Lab with Wazuh and ELK Stack"
description: "Complete guide to setting up enterprise-grade SIEM at home for threat detection and analysis practice."
date: 2025-02-01
category: "Tutorial"
tags: ["SIEM", "Wazuh", "ELK", "SOC", "Home Lab"]
image: "/images/projects/Net_Snoop.png"
author: "Rana Uzair Ahmad"
featured: true
---

## Introduction

As a SOC Analyst at the National Center of Cyber Security, I work daily with enterprise SIEM platforms. Setting up a home lab helped me practice threat detection and rule creation in a safe environment.

## Hardware Requirements

- **CPU**: 4 cores minimum (8 recommended)
- **RAM**: 16GB (32GB recommended)
- **Storage**: 100GB SSD minimum

## Step 1: Setting Up Wazuh

Wazuh is an open-source security monitoring platform that provides threat detection, integrity monitoring, incident response, and compliance.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-manager
```

## Step 2: Configuring ELK Stack

The Elastic Stack provides powerful search, analysis, and visualization capabilities for your security data.

### Elasticsearch Configuration

Configure Elasticsearch for optimal security event storage and retrieval with proper index management.

### Kibana Dashboards

Create custom dashboards for monitoring security events, failed login attempts, and suspicious network traffic.

## Step 3: Creating Custom Detection Rules

Custom rules allow you to detect threats specific to your environment and practice creating indicators of compromise.

## Conclusion

A home SOC lab is invaluable for any aspiring or current security analyst. It provides hands-on experience with enterprise tools in a controlled environment.
