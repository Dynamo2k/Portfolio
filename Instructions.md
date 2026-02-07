# COMPREHENSIVE PROMPT FOR CLAUDE OPUS: BUILD PROFESSIONAL CYBERSECURITY PORTFOLIO

Copy and paste this entire prompt to Claude Opus to build your portfolio from A to Z.

---

# BUILD A PROFESSIONAL CYBERSECURITY PORTFOLIO - COMPLETE IMPLEMENTATION

## CONTEXT & OBJECTIVE

You are tasked with building a **production-ready, professional cybersecurity portfolio** for Rana Uzair Ahmad, a cybersecurity professional working as a **SOC Analyst at National Center of Cyber Security** and **Penetration Tester at ZeroxInnovation**. 

This is NOT a student portfolio. This must be an **industry-grade website** that positions Rana as an experienced security professional ready for senior roles, consulting opportunities, or advanced positions.

## CRITICAL REQUIREMENTS

### 1. PROFESSIONAL POSITIONING (HIGHEST PRIORITY)
**DO NOT present this as a student portfolio.**

✅ **CORRECT Positioning:**
- "Cybersecurity Engineer | SOC Analyst | Penetration Tester"
- "SOC Analyst @ National Center of Cyber Security"
- "Penetration Tester @ ZeroxInnovation"
- Lead with professional experience and expertise

❌ **INCORRECT Positioning:**
- "5th Semester BS Cyber Security Student"
- Leading with education
- Student-focused language
- Academic emphasis

**Bio/About Page Structure:**
1. Professional headline with current roles
2. Professional experience and achievements (3-4 paragraphs)
3. Technical expertise and specializations
4. Professional timeline (most recent first: ZeroxInnovation → NCCS → Internship → Education)
5. Education mentioned last, briefly

### 2. RESUME DOWNLOAD ACCESSIBILITY (CRITICAL)
The resume download must be accessible from **EVERYWHERE**:

**Required Locations:**
- [ ] Navigation header (visible on all pages)
- [ ] Homepage hero section (large, prominent CTA)
- [ ] About page (multiple locations)
- [ ] Resume page (primary CTA)
- [ ] Contact page
- [ ] Footer (all pages)
- [ ] After project case studies ("Want to hire me? Download Resume")

**Button Design:**
- Large, prominent buttons with download icon
- Primary color (accent color)
- Hover state with animation
- Accessible via keyboard
- File name: "Rana_Uzair_Ahmad_Resume.pdf"
- Track downloads in analytics

### 3. SHOWCASE ALL GITHUB REPOSITORIES
**He has 34+ repositories** - showcase them properly:

**Featured Projects** (detailed case studies):
1. **NetSnoop** - Python packet analyzer (Scapy, networking)
2. **CortexCLI** - AI-powered security shell (C, AI integration)
3. **VortexTunnel** - SSH tunneling solution (Python)
4. **SSHield** - SSH security toolkit (Python, 4 stars)

**Additional Projects to Highlight:**
5. **SecureDork** - Google dorking tool (JavaScript, 4 stars, 2 forks)
6. **System-Auditor** - Security auditing tool (C, 4 stars)
7. **CyberGuard_agent** - SIEM agent (C, 4 stars) - developed during NCCS internship
8. **Pipex-Swiss-Army** - Pipeline implementation (Python, 4 stars, 1 fork)
9. **Password-Validator** - Assembly language (shows low-level expertise)
10. **Log_Monitor** - System monitoring (Shell, 4 stars)
11. **FastTex** - Rust project (shows learning modern languages)
12. **FEAS** - Faculty Evaluation System (JavaScript, 2 stars, 1 fork)
13. **QEC-FORM-Air-University** - Automation (Python, 2 stars)
14. **Remote-Control-Management-System** (RCMS) - JavaScript, 5 stars
15. **Customizeable-Search-Engine** - HTML, 5 stars, 1 fork
16. **SIEM_Solution** - JavaScript, 3 stars
17. **Key_logger** - C++ (educational purposes, 4 stars)

**Project Display Requirements:**
- Filterable gallery (All, Offensive, Defensive, Development, Research)
- Show GitHub stars and forks
- Link to live repos
- Tech stack badges for each project
- Category badges (Offensive/Defensive/Development)
- "View all 34+ repositories on GitHub" section

---

## TECHNICAL STACK & IMPLEMENTATION

### Technology Stack
**Use the following exact stack:**
- **Framework**: Astro (static site generator)
- **Styling**: Tailwind CSS with custom design system
- **Content**: MDX for blog posts (Markdown + React components)
- **Deployment**: Configured for Vercel
- **Version Control**: Git-ready with .gitignore

**Why This Stack:**
- Astro: Zero-JS by default, blazing fast, perfect for portfolios
- Tailwind: Rapid development, consistent design, easy customization
- MDX: Write blog posts in Markdown, embed components
- Vercel: One-click deployment, automatic HTTPS, global CDN

### Project Structure
```
portfolio/
├── src/
│   ├── components/
│   │   ├── Header.astro              # Navigation with Resume download
│   │   ├── Footer.astro              # Footer with Resume download
│   │   ├── Hero.astro                # Homepage hero with professional headline
│   │   ├── ResumeDownload.astro      # Reusable resume download button
│   │   ├── ProjectCard.astro         # Project card component
│   │   ├── ProjectFilter.astro       # Filter projects by category
│   │   ├── BlogCard.astro            # Blog post card
│   │   ├── SkillCategory.astro       # Skills display (NO percentage bars)
│   │   ├── Timeline.astro            # Professional experience timeline
│   │   ├── CertificationBadge.astro  # Certification display
│   │   └── ContactForm.astro         # Contact form with validation
│   │
│   ├── layouts/
│   │   ├── BaseLayout.astro          # Base layout with Header/Footer
│   │   ├── BlogLayout.astro          # Layout for blog posts
│   │   └── ProjectLayout.astro       # Layout for case studies
│   │
│   ├── pages/
│   │   ├── index.astro               # Homepage
│   │   ├── about.astro               # About page (professional focus)
│   │   ├── projects/
│   │   │   ├── index.astro           # Projects gallery
│   │   │   ├── netsnoop.astro        # Case study
│   │   │   ├── cortexcli.astro       # Case study
│   │   │   ├── vortextunnel.astro    # Case study
│   │   │   └── sshield.astro         # Case study
│   │   ├── blog/
│   │   │   ├── index.astro           # Blog listing
│   │   │   └── [slug].astro          # Dynamic blog posts
│   │   ├── resume.astro              # Resume page with download
│   │   └── contact.astro             # Contact page
│   │
│   ├── content/
│   │   ├── config.ts                 # Content collections config
│   │   ├── projects/                 # Project data (Markdown)
│   │   │   ├── netsnoop.md
│   │   │   ├── cortexcli.md
│   │   │   ├── sshield.md
│   │   │   └── [other projects].md
│   │   └── blog/                     # Blog posts (MDX)
│   │       ├── home-soc-lab.mdx
│   │       ├── tryhackme-journey.mdx
│   │       └── netsnoop-deep-dive.mdx
│   │
│   ├── styles/
│   │   └── global.css                # Global styles, Tailwind imports
│   │
│   └── utils/
│       ├── constants.ts              # Site constants, social links
│       └── helpers.ts                # Helper functions
│
├── public/
│   ├── images/
│   │   ├── projects/                 # Project screenshots
│   │   ├── blog/                     # Blog post images
│   │   ├── profile.jpg               # Professional headshot
│   │   └── og-image.jpg              # Open Graph image
│   ├── Rana_Uzair_Ahmad_Resume.pdf   # RESUME PDF (critical!)
│   ├── favicon.svg
│   └── robots.txt
│
├── astro.config.mjs                  # Astro configuration
├── tailwind.config.cjs               # Tailwind configuration
├── tsconfig.json                     # TypeScript config
├── package.json                      # Dependencies
├── .gitignore                        # Git ignore file
└── README.md                         # Setup instructions
```

---

## DESIGN SYSTEM SPECIFICATIONS

### Color Palette
**DO NOT use bright neon greens, reds, or "matrix hacker" aesthetic.**

**Professional Security Industry Palette:**

```css
:root {
  /* Backgrounds */
  --bg-primary: #0A0E27;        /* Deep navy blue */
  --bg-secondary: #1A1F3A;      /* Dark blue-gray */
  --bg-elevated: #242B4A;       /* Lighter surface */
  
  /* Accent Colors */
  --accent-primary: #00D9FF;    /* Cyber cyan */
  --accent-secondary: #7B68EE;  /* Muted purple */
  --accent-teal: #14B8A6;       /* Professional teal */
  
  /* Semantic Colors */
  --success: #10B981;           /* Muted green */
  --warning: #F59E0B;           /* Amber */
  --danger: #DC2626;            /* Crimson */
  --info: #3B82F6;              /* Blue */
  
  /* Text */
  --text-primary: #E5E7EB;      /* Off-white */
  --text-secondary: #9CA3AF;    /* Gray */
  --text-muted: #6B7280;        /* Muted gray */
  
  /* Security Domain Colors (for badges) */
  --offensive: #DC2626;         /* Red for offensive */
  --defensive: #3B82F6;         /* Blue for defensive */
  --forensics: #7B68EE;         /* Purple for forensics */
  --development: #10B981;       /* Green for development */
}
```

**Color Usage Rules:**
- Dark backgrounds for depth and professionalism
- Accent colors sparingly for CTAs and highlights
- Semantic colors for status and categories
- WCAG AA contrast ratios minimum (4.5:1 for text)
- All colors must be accessible

### Typography
**Font Stack:**

```css
/* Headings */
font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;

/* Body Text */
font-family: 'Inter', system-ui, sans-serif;

/* Code/Technical */
font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
```

**Type Scale (1.25 ratio):**
- Display (Hero): 48px - 64px (font-weight: 700)
- H1: 36px - 48px (font-weight: 700)
- H2: 28px - 36px (font-weight: 600)
- H3: 22px - 28px (font-weight: 600)
- H4: 18px - 22px (font-weight: 600)
- Body: 16px - 18px (font-weight: 400)
- Small: 14px (font-weight: 400)

**Typography Rules:**
- Line-height: 1.5 for body, 1.2 for headings
- Letter-spacing: -0.02em for large headings
- Monospace font ONLY for code blocks
- Inter font weights: 300, 400, 600, 700

### Spacing System
**8px base unit:**
- 0, 4px, 8px, 12px, 16px, 24px, 32px, 48px, 64px, 96px, 128px

**Usage:**
- Component padding: 16px minimum, 24px standard, 32px large
- Section spacing: 64px minimum between sections
- Grid gaps: 24px for cards, 32px for major divisions
- Margins: Use spacing scale consistently

### Component Design Standards

**Buttons:**
```css
/* Primary Button (Resume Download, CTAs) */
.btn-primary {
  background: var(--accent-primary);
  color: #000;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
}
.btn-primary:hover {
  background: #00BFEE;
  transform: translateY(-2px);
  box-shadow: 0 8px 16px rgba(0, 217, 255, 0.3);
}

/* Secondary Button */
.btn-secondary {
  border: 2px solid var(--accent-primary);
  color: var(--accent-primary);
  background: transparent;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
}

/* Download Button (special) */
.btn-download {
  background: var(--accent-primary);
  color: #000;
  padding: 14px 28px;
  border-radius: 8px;
  font-weight: 700;
  font-size: 16px;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.btn-download:hover {
  transform: scale(1.05);
  box-shadow: 0 0 24px rgba(0, 217, 255, 0.5);
}
```

**Cards:**
```css
.card {
  background: var(--bg-secondary);
  border: 1px solid rgba(0, 217, 255, 0.1);
  border-radius: 12px;
  padding: 24px;
  transition: all 300ms ease;
}
.card:hover {
  transform: translateY(-4px);
  border-color: var(--accent-primary);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}
```

**Navigation:**
- Sticky header with blur background on scroll
- Clean horizontal menu
- Active state: accent color underline
- Mobile: hamburger menu with slide-in drawer
- Resume download button: prominent in header

### Animation Principles

**DO IMPLEMENT:**
- Subtle fade-in on scroll (Intersection Observer)
- Hover lift on cards (2-4px translateY)
- Smooth page transitions (fade)
- Skill bar animations (fill on scroll-in)
- Button hover effects (scale, glow)
- Download button pulse/glow effect
- Staggered card animations

**DO NOT IMPLEMENT:**
- Matrix falling characters background
- Custom cursor following mouse
- Terminal boot loader animation
- Continuous pulsing/flashing
- Auto-playing animations that can't be paused
- Excessive glitch effects

**Animation Settings:**
- Duration: 200-300ms for most transitions
- Easing: ease-out for entrance, ease-in for exit
- Respect `prefers-reduced-motion` media query
- Provide option to disable animations

---

## SITE STRUCTURE & CONTENT

### HOMEPAGE

**Hero Section:**
```
Layout: Full viewport height, centered content

Professional Headline:
"Cybersecurity Engineer | SOC Analyst | Penetration Tester"

Subheadline:
"Defending digital infrastructure through offensive security and threat analysis"

Current Roles:
- SOC Analyst @ National Center of Cyber Security
- Penetration Tester @ ZeroxInnovation

CTAs (large buttons):
[Download Resume] (primary, prominent)
[View My Work] (secondary)
[Get in Touch] (tertiary)

Optional: Professional photo (circular, 250x250px)
```

**Quick Professional Bio (3-4 sentences):**
```
I'm a cybersecurity professional specializing in offensive security and threat analysis. 
Currently serving as SOC Analyst at the National Center of Cyber Security and Penetration 
Tester at ZeroxInnovation, I focus on threat detection, vulnerability assessment, and 
security tool development. With expertise in SIEM operations, penetration testing, and 
security automation, I help organizations identify and mitigate threats before they can 
be exploited.
```

**Featured Projects Section:**
- Grid: 4-6 project cards
- Projects: NetSnoop, CortexCLI, VortexTunnel, SSHield, SecureDork, System-Auditor
- Each card: Image, title, description, tech stack, category badge, GitHub link
- CTA: "View All 34+ Projects"

**Skills Overview:**
```
Categories:
- Offensive Security: Penetration Testing, Exploit Development, Web App Security
- Defensive Security: SOC Operations, SIEM (Wazuh, Splunk), Incident Response
- Tools: Burp Suite, Metasploit, Wireshark, Volatility, Autopsy, Ghidra
- Programming: Python, C/C++, Bash, Assembly, Rust
- Frameworks: MITRE ATT&CK, OWASP, NIST

Display: Tags or icon-based grid (NO percentage skill bars)
```

**Professional Stats:**
```
Grid display:
- 34+ Open Source Projects
- Top 4% on TryHackMe
- Top 900 HackTheBox
- 2+ Years Experience
```

**Certifications Highlight:**
- Display 4-6 key certifications with badges
- Link to full certifications on About page

**Recent Blog Posts (if applicable):**
- 2-3 latest posts
- Title, excerpt, date, read time
- CTA: "Read More Articles"

**Final CTA:**
```
"Looking for a cybersecurity professional?"

[Download Resume] (large, prominent)
[Contact Me] (secondary)
```

---

### ABOUT PAGE

**Professional Bio Section (PRIMARY FOCUS):**

**Header:**
```
Name: Rana Uzair Ahmad
Professional Headline: "Cybersecurity Engineer | SOC Analyst | Penetration Tester"
```

**Professional Summary (3-4 paragraphs):**
```
I'm a cybersecurity professional specializing in offensive security and threat analysis. 
Currently serving as a SOC Analyst at the National Center of Cyber Security, I monitor 
and respond to security incidents, analyze threat patterns, and develop custom detection 
rules for SIEM platforms including Wazuh and Splunk.

In my role as Penetration Tester at ZeroxInnovation, I conduct vulnerability assessments, 
perform ethical hacking engagements, and help organizations identify security weaknesses 
before malicious actors can exploit them. My work has contributed to securing critical 
infrastructure and preventing potential breaches.

Beyond my professional roles, I'm passionate about security research and tool development. 
I've created 34+ open-source security tools including NetSnoop (packet analyzer), CortexCLI 
(AI-powered security shell), and SSHield (SSH security toolkit). I'm also an active CTF 
competitor, ranking in the top 4% globally on TryHackMe and top 900 on HackTheBox.

I believe in continuous learning and community contribution. Through my blog and open-source 
work, I share knowledge and help others in the cybersecurity community grow their skills.
```

**Professional Experience Timeline:**
```
Visual Timeline (reverse chronological):

1. Penetration Tester @ ZeroxInnovation (April 2025 - Present)
   - Conduct vulnerability assessments and penetration testing
   - Identify and exploit security weaknesses in client systems
   - Provide detailed reports with remediation recommendations
   - Technologies: Burp Suite, Metasploit, Nmap, Kali Linux

2. SOC Analyst @ National Center of Cyber Security (Date - Present)
   - Monitor and respond to security incidents using SIEM platforms
   - Develop custom detection rules for Wazuh and Splunk
   - Analyze threat patterns and conduct threat hunting
   - Created C-based security agent for log collection
   - Technologies: Wazuh, Splunk, Kibana, ELK Stack, Python, C

3. Security Intern @ National Center of Cyber Security (Jun - Sep 2024)
   - Trained on SIEM tools (Wazuh, Splunk, Kibana)
   - Developed C-based agent for network scanning and log collection
   - Participated in security operations and incident response
   - Learned forensic analysis and threat detection

4. Education: BS Cyber Security @ Air University (2023 - Present)
   - Relevant Coursework: Advanced Cryptography, Network Security, Malware Analysis
   - Member of Cybersecurity Club and CTF team
   (Keep this brief - don't emphasize student status)
```

**Detailed Skills & Expertise:**

**Offensive Security:**
- Penetration Testing & Ethical Hacking
- Web Application Security (OWASP Top 10)
- Network Penetration Testing
- Exploit Development & Research
- Social Engineering Assessment
- Red Team Operations

**Defensive Security:**
- SOC Operations & Incident Response
- SIEM Platforms: Wazuh, Splunk, ELK Stack, Kibana
- Threat Hunting & Analysis
- Digital Forensics & Incident Analysis
- Malware Analysis (Static & Dynamic)
- Network Security Monitoring

**Security Tools & Platforms:**
- Offensive: Burp Suite, Metasploit, Nmap, SQLmap, John the Ripper, Hashcat
- Defensive: Wireshark, Zeek, Suricata, YARA, Volatility, Autopsy
- SIEM: Wazuh, Splunk, ELK Stack (Elasticsearch, Logstash, Kibana)
- Forensics: Autopsy, Volatility, FTK Imager, Sleuth Kit

**Programming & Scripting:**
- Python (Security automation, tool development)
- C/C++ (System-level programming, agents)
- Bash/Shell Scripting (Automation, log parsing)
- Assembly (Reverse engineering, exploit development)
- Rust (Learning - modern systems programming)
- JavaScript (Web security, automation)

**Frameworks & Methodologies:**
- MITRE ATT&CK Framework
- OWASP Testing Guide
- NIST Cybersecurity Framework
- CIS Controls
- Penetration Testing Execution Standard (PTES)

**Operating Systems:**
- Kali Linux / ParrotOS
- Ubuntu / Debian
- Windows internals

**CTF & Competition Achievements:**
```
Grid display with icons:

TryHackMe: Top 4% Globally
- 70+ rooms completed
- 100% completion in Offensive Path
- Profile: tryhackme.com/p/Dynamo2k1

HackTheBox: Top 900 Ranking
- Active participant
- Profile: hackthebox.com/profile/Dynamo2k1

CTFtime: Top 7 Ranking

Competition Wins:
- 1st Place - Air University CTF (2024)
- 2nd Place - Islamabad Cyber Challenge
- Best Pentester - Cyber Youth Competition
```

**Certifications (with badges):**
- NCCS Cybercrime and Forensics Lab Internship
- MITRE ATT&CK Framework (Udemy)
- Reverse Engineering & Malware Analysis (REMASM+)
- OSCP Preparation Series (Parts 1-3)
- x64dbg Static Analysis
- TryHackMe Advent of Cyber 2024

Include: Official badges, verification links, certificate PDFs

**Current Learning & Research:**
- Advanced malware analysis techniques
- Cloud security (AWS/Azure)
- Rust programming for security tools
- AI/ML in cybersecurity
- Red team tactics and techniques

**Download Resume Section (Prominent):**
```
Large card with:
"Want to know more about my experience?"

[Download Full Resume] (large button)

PDF format, ATS-friendly
Last updated: February 2026
```

---

### PROJECTS PAGE

**Page Header:**
```
Title: "Security Projects & Research"
Subtitle: "Open-source security tools and research from 34+ GitHub repositories"

Quick Links:
[Download Resume]
[View All on GitHub]
```

**Project Filtering:**
```
Tabs or Buttons:
- All Projects (34+)
- Featured (6-8)
- Offensive Tools
- Defensive Tools
- Development
- Research & Learning

Display: Active filter highlighted
```

**Featured Projects (6-8 projects):**

Create detailed cards for:
1. **NetSnoop** (Packet Analyzer)
2. **CortexCLI** (AI-Powered Security Shell)
3. **VortexTunnel** (SSH Tunneling)
4. **SSHield** (SSH Security Toolkit)
5. **SecureDork** (Google Dorking Tool)
6. **System-Auditor** (Security Auditing)
7. **CyberGuard_agent** (SIEM Agent)
8. **Pipex-Swiss-Army** (Pipeline Implementation)

**Project Card Components:**
```
Each card includes:
- Screenshot/Thumbnail (high quality)
- Project Name
- One-line description
- Tech Stack Tags (Python, C, Rust, etc.)
- Category Badge (Offensive/Defensive/Development)
- GitHub Stars (if any)
- "View Details" → Case Study (for featured)
- "View on GitHub" → Repository link
```

**Additional Projects Grid:**
Display smaller cards for:
- Password-Validator (Assembly)
- Log_Monitor (Shell)
- FastTex (Rust)
- FEAS (JavaScript)
- QEC-FORM-Air-University (Python)
- Remote-Control-Management-System (JavaScript)
- Customizeable-Search-Engine (HTML)
- SIEM_Solution (JavaScript)
- Key_logger (C++) - with educational disclaimer
- And all others from 34 repositories

**GitHub Integration:**
```
Section: "Explore All Projects"

Statistics:
- Total Repositories: 34+
- Total Stars: [Calculate from repos]
- Languages: Python, C, C++, JavaScript, Rust, Assembly, Shell

[View All on GitHub] (large button)
Link: https://github.com/Dynamo2k1
```

**Call to Action:**
```
"Interested in collaboration?"

[Download Resume]
[Contact Me]
```

---

### CASE STUDY TEMPLATE (For 4 Major Projects)

**Create detailed case studies for:**
1. NetSnoop
2. CortexCLI
3. VortexTunnel
4. SSHield

**Case Study Structure:**

**1. Project Header:**
```
Project Name: [e.g., NetSnoop]
Tagline: Advanced Packet Analyzer for Network Security
Tech Stack: Python, Scapy, Matplotlib, Argparse
Category: Offensive/Defensive
GitHub: [Link with stars]
Documentation: [Link if available]

[Download Resume] (in header)
```

**2. Project Overview:**
```
Problem Statement:
"What security challenge does this address?"

Objectives:
"What were you trying to achieve?"

Target Users:
"Penetration testers, security researchers, students"

My Role:
"Solo developer - Full architecture, implementation, documentation"
```

**3. Technical Deep Dive:**
```
Architecture:
- System design explanation
- Data flow diagram (create with ASCII art or describe)
- Component breakdown

Core Features:
1. Multi-protocol support (IPv4, IPv6, TCP, UDP, ICMP, DNS, DHCP)
2. Real-time packet capture and analysis
3. PCAP file export for Wireshark
4. Custom BPF filtering
5. Protocol statistics and visualization

Implementation Highlights:
- Scapy library for packet dissection
- Multi-threaded packet processing
- Efficient memory management for high-speed networks
- Custom protocol parsers

Code Example:
```python
# Example: Custom packet handler
def packet_handler(packet):
    if packet.haslayer(TCP):
        analyze_tcp(packet)
    elif packet.haslayer(UDP):
        analyze_udp(packet)
    # Process and display packet info
```
```

**4. Challenges & Solutions:**
```
Challenge 1: Performance Optimization
- Problem: Packet loss at high network speeds
- Solution: Implemented multi-threaded processing and efficient buffering
- Result: Reduced packet loss from 15% to <2%

Challenge 2: Protocol Parsing Accuracy
- Problem: Complex protocol variations
- Solution: Robust error handling and fallback mechanisms
- Result: 99%+ accurate protocol identification

Lessons Learned:
"What I'd do differently if starting over"
```

**5. Results & Impact:**
```
Achievements:
- 4 GitHub stars
- Used by security students for learning
- Featured in university coursework

Metrics:
- Supports 10+ network protocols
- Processes 1000+ packets/second
- 500+ lines of Python code
- Comprehensive documentation

Real-world Use Cases:
- Network security training
- Penetration testing reconnaissance
- Protocol analysis and debugging
```

**6. Visual Documentation:**
```
Include:
- Screenshot of tool running
- Example output (packet capture)
- Architecture diagram
- Performance charts (if applicable)
```

**7. Future Roadmap:**
```
Planned Features:
- GUI interface
- Additional protocol support
- Machine learning for anomaly detection
- Export to multiple formats
```

**8. Related Work:**
```
Blog Posts:
- "Building NetSnoop: A Deep Dive into Python Packet Analysis"
- "Network Security Fundamentals with NetSnoop"

GitHub Repository:
[Link to well-documented repo]
```

---

### BLOG PAGE

**Page Header:**
```
Title: "Technical Writing & Research"
Subtitle: "CTF write-ups, security insights, and technical deep-dives"

Search: (Optional search bar)
Filters: [All] [CTF Write-ups] [Tutorials] [Reviews] [Research]
```

**Blog Post Grid:**
```
Card Layout:
- Featured image (if applicable)
- Title
- Excerpt (2-3 sentences)
- Author: Rana Uzair Ahmad
- Date
- Read time
- Category tags
- [Read More] button
```

**Initial Blog Posts to Create:**

**Post 1: "Building a SOC Home Lab with Wazuh and ELK Stack"**
```
Category: Technical Guide
Content:
- My experience setting up SIEM at home
- Hardware requirements
- Wazuh configuration
- ELK Stack setup
- Creating custom detection rules
- Dashboard examples (screenshots)
- Lessons learned
- Resources and recommendations

Read time: 10-12 minutes
```

**Post 2: "My Journey to Top 4% on TryHackMe"**
```
Category: Personal / CTF
Content:
- How I got started
- Learning path and strategy
- Favorite rooms and why
- Challenges that taught me the most
- Tips for beginners
- Resources I used
- How it helped my career

Read time: 8-10 minutes
```

**Post 3: "NetSnoop Deep Dive: Building a Python Packet Analyzer"**
```
Category: Technical / Project
Content:
- Why I built NetSnoop
- Architecture decisions
- Code walkthrough
- Performance optimization
- Challenges and solutions
- How to use it
- Future improvements

Read time: 12-15 minutes
```

**Post 4: "MITRE ATT&CK Framework: Practical Guide for SOC Analysts"**
```
Category: Technical Guide
Content:
- Understanding ATT&CK
- How I use it in SOC work
- Mapping threats to tactics
- Real-world examples
- Integration with SIEM
- Threat hunting with ATT&CK
- Resources

Read time: 10-12 minutes
```

**Post 5: "5 CTF Challenges That Changed My Security Mindset"**
```
Category: CTF Write-ups
Content:
- Challenge 1: [Name] - What I learned
- Challenge 2: [Name] - Solution walkthrough
- Challenge 3: [Name] - Key takeaways
- Challenge 4: [Name] - Techniques used
- Challenge 5: [Name] - How it applies to real-world
- Links to platforms
- Recommendations for similar challenges

Read time: 15-18 minutes
```

**Blog Post Template:**
```
Structure for each post:
1. Compelling title
2. Author info with photo
3. Publication date
4. Read time estimate
5. Table of contents (for long posts)
6. Introduction
7. Main content with headings
8. Code blocks (syntax highlighted)
9. Screenshots and diagrams
10. Key takeaways / Conclusion
11. Tags and categories
12. Related posts
13. Share buttons
14. CTA: Download Resume
```

---

### RESUME PAGE

**Page Header:**
```
Title: "Resume / CV"
Last Updated: February 2026

[Download PDF Resume] (VERY LARGE, PROMINENT)
```

**Interactive Resume Display:**

**Professional Summary:**
```
Cybersecurity professional with 2+ years of experience in SOC operations and 
penetration testing. Specializing in threat detection, vulnerability assessment, 
and security tool development. Proven track record in SIEM operations (Wazuh, 
Splunk), penetration testing, and creating custom security solutions. Top 4% 
globally on TryHackMe with 34+ open-source security projects.
```

**Professional Experience:**
```
Penetration Tester
ZeroxInnovation | April 2025 - Present
• Conduct vulnerability assessments and penetration testing for client systems
• Identify and exploit security weaknesses in web applications and networks
• Provide detailed security reports with remediation recommendations
• Technologies: Burp Suite, Metasploit, Nmap, Kali Linux

SOC Analyst
National Center of Cyber Security | [Date] - Present
• Monitor and respond to security incidents using SIEM platforms (Wazuh, Splunk)
• Develop custom detection rules and threat hunting queries
• Analyze threat patterns and conduct incident response
• Created C-based security agent for automated log collection
• Technologies: Wazuh, Splunk, Kibana, ELK Stack, Python, C

Security Intern
National Center of Cyber Security | Jun - Sep 2024
• Trained on SIEM tools including Wazuh, Splunk, and Kibana
• Developed C-based agent for network scanning and log collection
• Participated in security operations and incident response
• Learned forensic analysis and threat detection techniques
```

**Education:**
```
BS Cyber Security
Air University, Islamabad | 2023 - Present
• Relevant Coursework: Advanced Cryptography, Network Security, Malware Analysis
• Member of Cybersecurity Club and CTF team
```

**Technical Skills:**
```
Offensive Security: Penetration Testing, Web App Security, Network Security, 
Exploit Development

Defensive Security: SOC Operations, SIEM (Wazuh, Splunk, ELK), Threat Hunting, 
Incident Response, Digital Forensics, Malware Analysis

Tools: Burp Suite, Metasploit, Nmap, Wireshark, Volatility, Autopsy, Ghidra, 
IDA Pro, John the Ripper, Hashcat

Programming: Python, C/C++, Bash, Assembly, Rust (learning), JavaScript

Frameworks: MITRE ATT&CK, OWASP, NIST, CIS Controls
```

**Certifications:**
```
- NCCS Cybercrime and Forensics Lab Internship (2024)
- MITRE ATT&CK Framework (2024)
- Reverse Engineering & Malware Analysis - REMASM+ (2024)
- OSCP Preparation Series - Parts 1, 2, 3 (2024)
- x64dbg Static Analysis (2024)
- TryHackMe Advent of Cyber 2024
```

**Notable Projects:**
```
- NetSnoop - Advanced packet analyzer (Python, Scapy)
- CortexCLI - AI-powered security shell (C, AI Integration)
- SSHield - SSH security toolkit (Python)
- VortexTunnel - SSH tunneling solution (Python)
- 34+ open-source security projects on GitHub
```

**Achievements:**
```
- Top 4% on TryHackMe (70+ rooms completed)
- Top 900 on HackTheBox
- Top 7 on CTFtime.org
- 1st Place - Air University CTF (2024)
- 2nd Place - Islamabad Cyber Challenge
```

**Download Section:**
```
Large, Prominent:

"Ready to discuss opportunities?"

[Download Full Resume (PDF)] (extra large button)

PDF format, ATS-friendly
File size: ~200KB
Last updated: February 2026
```

---

### CONTACT PAGE

**Page Header:**
```
Title: "Get in Touch"
Subtitle: "Let's discuss cybersecurity opportunities and collaborations"
```

**Two-Column Layout:**

**Left: Contact Form**
```
Title: "Send Me a Message"

Fields:
- Name (required)
- Email (required, validated)
- Subject (optional)
- Message (required, textarea, min 10 chars)

Button: "Send Message" with icon

States:
- Default: Ready to send
- Loading: "Sending..." with spinner
- Success: "Message sent! I'll get back to you within 24-48 hours."
- Error: "Something went wrong. Please email me directly."

Integration: Use Formspree or Web3Forms (free services)
Action: https://formspree.io/f/[your-form-id]
```

**Right: Contact Information**

**Professional Links:**
```
Email: ranauzair370@gmail.com
(or hide email, use form only to avoid spam)

Phone: +92 344 5001600
(optional - consider privacy)

Location: Islamabad, Pakistan
```

**Social & Professional Profiles:**
```
GitHub: github.com/Dynamo2k1 (34 repositories)
LinkedIn: linkedin.com/in/rana-uzair-ahmad-82b8b6223
TryHackMe: tryhackme.com/p/Dynamo2k1 (Top 4%)
HackTheBox: hackthebox.com (Top 900)
Website: dynamo2k1.github.io
Blog: ciphervanguard.wordpress.com
Instagram: @ra.na_uzair_ahmad
Facebook: uzair.ge.56
```

**Availability:**
```
Status: Open to full-time opportunities
Available for freelance security consulting
Interested in security research collaborations

Response Time: Usually within 24-48 hours
Timezone: PKT (UTC+5)
```

**PGP Key (Optional):**
```
Section: "Secure Communication"

Fingerprint: [Display PGP key fingerprint]

[Download Public Key (.asc)] button

Brief note: "For encrypted communication, use my PGP public key"
```

**Download Resume:**
```
Prominent section:

"Want to know more about my background?"

[Download My Resume] (large button)
```

---

## PERSONAL INFORMATION & CONTENT

**Use this exact information throughout:**

**Name:** Rana Uzair Ahmad

**Professional Headline:**
"Cybersecurity Engineer | SOC Analyst | Penetration Tester"

**Current Positions:**
- SOC Analyst @ National Center of Cyber Security
- Penetration Tester @ ZeroxInnovation (April 2025 - Present)

**Location:** Islamabad, Pakistan

**Contact:**
- Email: ranauzair370@gmail.com
- Phone: +92 344 5001600

**Social Links:**
- GitHub: https://github.com/Dynamo2k1
- LinkedIn: https://linkedin.com/in/rana-uzair-ahmad-82b8b6223
- TryHackMe: https://tryhackme.com/p/Dynamo2k1
- HackTheBox: https://hackthebox.com (profile link)
- Personal Site: https://dynamo2k1.github.io
- Blog: https://ciphervanguard.wordpress.com
- Instagram: https://www.instagram.com/ra.na_uzair_ahmad/
- Facebook: https://www.facebook.com/uzair.ge.56

**Education:**
BS Cyber Security @ Air University, Islamabad (2023 - Present)

**Key Stats:**
- 34+ GitHub repositories
- Top 4% TryHackMe
- Top 900 HackTheBox
- Top 7 CTFtime.org
- 2+ years cybersecurity experience

---

## SEO & META TAGS

**Homepage Meta Tags:**
```html
<title>Rana Uzair Ahmad | Cybersecurity Engineer | SOC Analyst | Penetration Tester</title>
<meta name="description" content="Cybersecurity professional specializing in SOC operations, penetration testing, and security tool development. Top 4% on TryHackMe with 34+ open-source projects.">
<meta name="keywords" content="cybersecurity, penetration testing, SOC analyst, security engineer, ethical hacking, SIEM, Wazuh, Splunk">

<!-- Open Graph -->
<meta property="og:title" content="Rana Uzair Ahmad | Cybersecurity Engineer">
<meta property="og:description" content="SOC Analyst & Penetration Tester specializing in threat detection and security automation">
<meta property="og:image" content="https://yoursite.com/og-image.jpg">
<meta property="og:url" content="https://yoursite.com">
<meta property="og:type" content="website">

<!-- Twitter Card -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Rana Uzair Ahmad | Cybersecurity Engineer">
<meta name="twitter:description" content="SOC Analyst & Penetration Tester">
<meta name="twitter:image" content="https://yoursite.com/og-image.jpg">
```

**Structured Data (JSON-LD):**
```json
{
  "@context": "https://schema.org",
  "@type": "Person",
  "name": "Rana Uzair Ahmad",
  "jobTitle": "Cybersecurity Engineer | SOC Analyst | Penetration Tester",
  "description": "Cybersecurity professional specializing in SOC operations and penetration testing",
  "url": "https://yourportfolio.com",
  "image": "https://yourportfolio.com/profile.jpg",
  "sameAs": [
    "https://github.com/Dynamo2k1",
    "https://linkedin.com/in/rana-uzair-ahmad-82b8b6223",
    "https://tryhackme.com/p/Dynamo2k1",
    "https://dynamo2k1.github.io"
  ],
  "worksFor": [
    {
      "@type": "Organization",
      "name": "ZeroxInnovation"
    },
    {
      "@type": "Organization",
      "name": "National Center of Cyber Security"
    }
  ],
  "alumniOf": {
    "@type": "EducationalOrganization",
    "name": "Air University"
  },
  "knowsAbout": [
    "Penetration Testing",
    "SOC Operations",
    "SIEM",
    "Digital Forensics",
    "Malware Analysis",
    "Ethical Hacking"
  ]
}
```

---

## PERFORMANCE & OPTIMIZATION REQUIREMENTS

### Performance Targets (Lighthouse)
- Performance: 90+
- Accessibility: 95+
- Best Practices: 95+
- SEO: 100

### Core Web Vitals
- Largest Contentful Paint (LCP): < 2.5s
- First Input Delay (FID): < 100ms
- Cumulative Layout Shift (CLS): < 0.1

### Optimization Strategies

**Images:**
- Format: WebP with JPEG fallback
- Lazy loading for below-fold images
- Responsive images with srcset
- Compression: < 200KB per image
- Dimensions: Proper aspect ratios
- Alt text: Descriptive for all images

**Code:**
- Minify CSS and JavaScript
- Inline critical CSS in <head>
- Defer non-critical JavaScript
- Tree-shaking unused code
- Code splitting for routes

**Fonts:**
- Use system fonts (Inter is available on most systems)
- If custom fonts: WOFF2 format only
- Font-display: swap
- Preload critical fonts

**Caching:**
- Cache-Control headers for static assets
- Service worker for offline support (optional)
- Version assets for cache busting

---

## ACCESSIBILITY REQUIREMENTS (WCAG 2.1 AA)

### Keyboard Navigation
- All interactive elements accessible via Tab
- Visible focus indicators (2px accent color outline)
- Skip to main content link
- Logical tab order
- Escape to close modals/menus

### Screen Readers
- Semantic HTML5 (header, nav, main, article, section, footer)
- Proper heading hierarchy (only one h1 per page)
- ARIA labels where semantic HTML isn't sufficient
- Alt text for all meaningful images
- Empty alt="" for decorative images
- Form labels associated with inputs

### Visual Accessibility
- Color contrast ratios: 4.5:1 for text, 3:1 for large text
- Don't rely on color alone for information
- Text resizable to 200% without breaking layout
- No flashing content > 3 times per second
- Sufficient spacing between interactive elements

### Motion & Animation
- Respect `prefers-reduced-motion` media query
- Provide option to disable animations in settings
- No auto-playing content without controls
- Pausable animations

### Forms
- Clear labels for all inputs
- Required fields marked with asterisk and aria-required
- Error messages with descriptive text
- Success states clearly indicated
- Instructions before form fields

---

## RESPONSIVE DESIGN REQUIREMENTS

### Breakpoints
```css
/* Mobile First */
/* Base: 320px - 767px */

/* Tablet */
@media (min-width: 768px) { }

/* Desktop */
@media (min-width: 1024px) { }

/* Large Desktop */
@media (min-width: 1440px) { }
```

### Mobile Behavior (320px - 767px)
- Single column layout
- Hamburger menu
- Stacked cards
- Full-width images
- Large touch targets (44x44px minimum)
- Font size: 16px minimum (no zoom required)
- Resume download button: Extra large
- Simplified navigation
- Hide less critical content

### Tablet Behavior (768px - 1023px)
- Two-column grid for projects
- Horizontal navigation (if space permits)
- Larger images
- More whitespace

### Desktop Behavior (1024px+)
- Three-column grid for projects
- Full horizontal navigation
- Larger hero section
- Side-by-side layouts
- Maximum content width: 1200px (centered)

---

## DEPLOYMENT & HOSTING

### Vercel Configuration

**Install Vercel CLI:**
```bash
npm install -g vercel
```

**Deploy:**
```bash
vercel
```

**Configuration (vercel.json):**
```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "devCommand": "npm run dev",
  "installCommand": "npm install",
  "framework": "astro",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/"
    }
  ]
}
```

**Environment Variables:**
- None required (static site)

**Custom Domain:**
- Add custom domain in Vercel dashboard
- Configure DNS records
- Automatic HTTPS certificate

---

## DELIVERABLES CHECKLIST

When you complete the portfolio, provide:

- [ ] Complete, working website
- [ ] All pages implemented (Home, About, Projects, Blog, Resume, Contact)
- [ ] 34+ projects from GitHub showcased
- [ ] 4 detailed case studies (NetSnoop, CortexCLI, VortexTunnel, SSHield)
- [ ] 5 initial blog posts written
- [ ] Resume download accessible from all pages
- [ ] Professional design (NO matrix/neon aesthetic)
- [ ] Fully responsive (mobile, tablet, desktop)
- [ ] WCAG AA accessible
- [ ] Lighthouse scores 90+
- [ ] SEO optimized (meta tags, structured data)
- [ ] Deployed to Vercel
- [ ] README.md with:
  - Setup instructions
  - How to add blog posts
  - How to add projects
  - How to update resume
  - How to deploy
- [ ] Clean, documented code
- [ ] Git repository initialized
- [ ] .gitignore file
- [ ] package.json with all dependencies

---

## FINAL QUALITY CHECKS

Before considering the portfolio complete, verify:

### Design Quality
- [ ] Professional appearance (NOT student project)
- [ ] Consistent spacing and alignment
- [ ] No bright neon colors (matrix theme removed)
- [ ] Typography hierarchy clear
- [ ] All images optimized and loading properly
- [ ] Dark theme looks professional

### Content Quality
- [ ] Bio leads with professional roles, NOT education
- [ ] "SOC Analyst | Penetration Tester" prominent everywhere
- [ ] All 34 GitHub projects visible
- [ ] Resume download works on all pages
- [ ] No typos or grammatical errors
- [ ] All links working
- [ ] Contact form functional

### Technical Quality
- [ ] Lighthouse Performance 90+
- [ ] Lighthouse Accessibility 95+
- [ ] All images have alt text
- [ ] Keyboard navigation works
- [ ] Mobile fully responsive
- [ ] No console errors
- [ ] Fast page load (< 3s)
- [ ] SEO meta tags present

### Professional Positioning
- [ ] Reads as experienced professional
- [ ] NOT presented as student
- [ ] Professional experience highlighted
- [ ] Education de-emphasized
- [ ] Career-focused, not academic-focused

---

## SUCCESS CRITERIA

The portfolio is successful when:

1. **First Impression**: Visitor immediately sees "Cybersecurity Engineer | SOC Analyst | Penetration Tester"
2. **Professional Credibility**: Design and content position Rana as industry-ready professional
3. **Resume Access**: Download button is visible and prominent on every page
4. **Project Showcase**: All 34 GitHub projects are accessible and well-presented
5. **Technical Excellence**: Lighthouse scores confirm quality implementation
6. **Accessibility**: Everyone can navigate and use the site
7. **Performance**: Site loads quickly on all devices and connections
8. **SEO**: Search engines can properly index and rank the content
9. **Scalability**: Easy to add new blog posts, projects, and updates

---

## IMPLEMENTATION STEPS

**Step 1: Setup Project**
```bash
npm create astro@latest portfolio
cd portfolio
npm install
npm install -D tailwindcss @astrojs/tailwind
npx astro add tailwind
```

**Step 2: Configure Tailwind**
- Create custom color palette
- Set up spacing system
- Configure typography
- Add custom components

**Step 3: Build Components**
- Header with Resume download
- Footer with Resume download
- ResumeDownload component (reusable)
- ProjectCard component
- BlogCard component
- Timeline component
- SkillCategory component
- ContactForm component

**Step 4: Create Pages**
- Homepage (professional hero, featured projects, stats)
- About (professional bio, experience timeline, skills)
- Projects (filterable gallery, case studies)
- Blog (article grid, blog posts)
- Resume (interactive display + download)
- Contact (form + info)

**Step 5: Add Content**
- Professional bio and summary
- Experience timeline
- All 34 projects data
- 4 detailed case studies
- 5 initial blog posts
- Skills and certifications

**Step 6: Optimize**
- Image optimization
- Code minification
- Accessibility testing
- Performance testing
- SEO implementation

**Step 7: Deploy**
- Initialize Git
- Push to GitHub
- Deploy to Vercel
- Configure custom domain
- Verify production

**Step 8: Document**
- Write comprehensive README
- Add content management guide
- Include deployment instructions
- Document code structure

---

## RESOURCES & REFERENCES

**Design Inspiration:**
- Avoid: Matrix themes, neon colors, custom cursors
- Reference: Modern SaaS websites, professional portfolios
- Example colors: Deep blues, muted cyans, professional dark themes

**Technical Resources:**
- Astro docs: https://docs.astro.build
- Tailwind docs: https://tailwindcss.com
- MDX docs: https://mdxjs.com
- Vercel docs: https://vercel.com/docs

**Accessibility:**
- WCAG guidelines: https://www.w3.org/WAI/WCAG21/quickref/
- WebAIM: https://webaim.org

**Performance:**
- Web.dev: https://web.dev
- Lighthouse: https://developers.google.com/web/tools/lighthouse

---

## IMPORTANT REMINDERS

1. **NO Matrix Theme**: Remove all matrix backgrounds, custom cursors, terminal loaders
2. **Professional First**: Lead with "SOC Analyst | Penetration Tester", not student status
3. **Resume Everywhere**: Download button on EVERY page
4. **Showcase All Work**: 34 GitHub projects, not just 4-5
5. **Modern Design**: Professional security industry aesthetic, not gamer/hacker theme
6. **Mobile First**: Build for mobile, enhance for desktop
7. **Accessibility**: WCAG AA minimum, test with keyboard and screen reader
8. **Performance**: Fast loading, optimized images, minimal JavaScript
9. **SEO**: Proper meta tags, structured data, sitemap
10. **Documentation**: Clear README for future updates

---

## BEGIN IMPLEMENTATION

Start building the portfolio now following these specifications exactly. Create a production-ready website that positions Rana Uzair Ahmad as an experienced cybersecurity professional with easy access to his resume from every page.

Focus on:
- Professional design and content
- Resume download prominence
- All 34 GitHub projects showcased
- Fast, accessible, SEO-optimized implementation
- Modern tech stack (Astro + Tailwind)

Good luck building an industry-grade cybersecurity portfolio!
