# BUILD PROFESSIONAL CYBERSECURITY PORTFOLIO - BLOG-CENTRIC DESIGN

## CONTEXT & CRITICAL CHANGES

You are building a **production-ready cybersecurity portfolio** for Rana Uzair Ahmad with these CRITICAL requirements:

### 🎨 DESIGN CHANGES (HIGHEST PRIORITY)

**1. MATTE BLACK BACKGROUND - NOT BLUE!**
```css
/* PRIMARY BACKGROUND */
--bg-primary: #0d0d0d;        /* Matte black - main background */
--bg-secondary: #1a1a1a;      /* Slightly lighter black for cards */
--bg-elevated: #262626;       /* Elevated surfaces */
--bg-hover: #303030;          /* Hover states */
```

**2. FIX FORMATTING ISSUES**
- ❌ NO markdown symbols showing (##, ###, **, ---)
- ✅ Proper HTML rendering
- ✅ Clean, formatted text
- ✅ Professional typography
- ✅ Readable spacing

**3. BLOG-STYLE HOMEPAGE**
Inspired by jaxafed.github.io and profparadox.vercel.app:
- Latest blog posts/projects as cards
- Preview images for each post
- Tags and categories
- Clean, scannable layout
- NOT traditional hero section

---

## NEW COLOR PALETTE - MATTE BLACK THEME

```css
:root {
  /* Backgrounds - Matte Black Theme */
  --bg-primary: #0d0d0d;           /* Deep matte black */
  --bg-secondary: #1a1a1a;         /* Card background */
  --bg-elevated: #262626;          /* Elevated cards */
  --bg-hover: #303030;             /* Hover state */
  --bg-input: #1f1f1f;             /* Input fields */
  
  /* Accent Colors - Professional Cyber */
  --accent-primary: #00ff9f;       /* Bright cyan-green (main CTA) */
  --accent-secondary: #00d4ff;     /* Electric blue */
  --accent-purple: #a78bfa;        /* Soft purple */
  --accent-orange: #ff6b35;        /* Orange accent */
  
  /* Semantic Colors */
  --offensive: #ff6b6b;            /* Red for offensive security */
  --defensive: #4dabf7;            /* Blue for defensive */
  --forensics: #be4bdb;            /* Purple for forensics */
  --development: #51cf66;          /* Green for development */
  --research: #ff922b;             /* Orange for research */
  
  /* Text Colors */
  --text-primary: #e8e8e8;         /* Off-white text */
  --text-secondary: #a0a0a0;       /* Gray text */
  --text-muted: #6e6e6e;           /* Muted text */
  --text-heading: #ffffff;         /* Pure white for headings */
  
  /* Borders & Dividers */
  --border-subtle: #2a2a2a;        /* Subtle borders */
  --border-medium: #3a3a3a;        /* Medium borders */
  --border-strong: #4a4a4a;        /* Strong borders */
  --border-accent: #00ff9f;        /* Accent borders */
  
  /* Status Colors */
  --success: #10b981;
  --warning: #f59e0b;
  --error: #ef4444;
  --info: #3b82f6;
}
```

**Color Usage Rules:**
- Background: Always matte black (#0d0d0d), never blue
- Accent: Use bright cyan-green (#00ff9f) for CTAs and highlights
- Text: High contrast on black background
- Cards: Subtle gray (#1a1a1a) with accent borders on hover
- All colors WCAG AAA compliant on black background

---

## NEW HOMEPAGE LAYOUT - BLOG-STYLE

### Homepage Structure (NOT Traditional Portfolio)

**Header:**
```
[Logo/Name]                    [Blog] [Projects] [CTF] [About] [Resume] [Contact]
                               [Download Resume] button (accent color)
```

**Hero Section (Minimal):**
```
Rana Uzair Ahmad
Cybersecurity Engineer | SOC Analyst | Penetration Tester

SOC Analyst @ NCCS | Penetration Tester @ ZeroxInnovation
Top 4% TryHackMe | 34+ Security Projects

[View Latest Posts] [Download Resume]
```

**Main Content - Blog/Project Feed:**
```
Layout: Grid of cards (3 columns desktop, 2 tablet, 1 mobile)

Each card:
┌─────────────────────────────────────┐
│  [Preview Image]                    │
│                                      │
│  [Category Badge] [Date]            │
│  Project/Post Title                 │
│  Brief description (2 lines)        │
│  [Tech Stack Tags]                  │
│  [Read More →]                      │
└─────────────────────────────────────┘

Categories: CTF Writeups, Projects, Technical Posts, Research
```

**Sidebar (Desktop):**
```
About Me (Quick Bio)
───────────────────
Brief professional summary
Current roles
Top skills

Trending Tags
───────────────────
Python  Penetration Testing
SIEM    CTF    Malware Analysis
Forensics    Web Security

Recent Activity
───────────────────
- Latest GitHub commit
- New certification
- CTF ranking update

Stats
───────────────────
34+ Projects
Top 4% TryHackMe
500+ GitHub Stars
```

**Footer:**
Social links, newsletter, copyright

---

## HOMEPAGE CONTENT - LATEST POSTS/PROJECTS

### Featured Content (Display as Cards)

**Post/Project Card 1: NetSnoop**
```
Category: Featured Project | Development
Image: Screenshot of NetSnoop terminal output
Title: "NetSnoop - Advanced Python Packet Analyzer"
Description: "Built a high-performance packet sniffer supporting 10+ protocols with PCAP export and BPF filtering for penetration testing workflows."
Tags: Python, Scapy, Networking, Security
Read More: /projects/netsnoop
```

**Post/Project Card 2: SOC Home Lab**
```
Category: Blog Post | Tutorial
Image: SIEM dashboard screenshot
Title: "Building a Professional SOC Lab with Wazuh and ELK Stack"
Description: "Complete guide to setting up enterprise-grade SIEM at home for threat detection and analysis practice."
Tags: SIEM, Wazuh, Splunk, ELK, SOC
Read More: /blog/soc-home-lab
```

**Post/Project Card 3: TryHackMe Journey**
```
Category: CTF Writeup | Achievement
Image: TryHackMe ranking badge
Title: "My Path to Top 4% on TryHackMe: Strategies & Favorite Challenges"
Description: "Sharing my learning journey, favorite CTF rooms, and techniques that helped me reach top 4% globally."
Tags: CTF, TryHackMe, Learning, Pentesting
Read More: /blog/tryhackme-journey
```

**Post/Project Card 4: CortexCLI**
```
Category: Featured Project | AI Security
Image: Terminal with AI commands
Title: "CortexCLI - AI-Powered Security Shell in C"
Description: "Developed an intelligent Linux shell with Google Gemini integration and built-in security filtering for dangerous commands."
Tags: C, AI, Security, CLI
Read More: /projects/cortexcli
```

**Post/Project Card 5: MITRE ATT&CK Guide**
```
Category: Blog Post | SOC
Image: ATT&CK matrix visualization
Title: "Practical MITRE ATT&CK Framework for SOC Analysts"
Description: "Real-world application of ATT&CK tactics in threat hunting and SIEM rule creation based on my SOC experience."
Tags: MITRE, Threat Hunting, SOC, SIEM
Read More: /blog/mitre-attack-guide
```

**Post/Project Card 6: SSHield**
```
Category: Featured Project | Security Tool
Image: SSH authentication diagram
Title: "SSHield - Comprehensive SSH Security Toolkit"
Description: "Python-based toolkit for SSH hardening, key management, and secure authentication workflows."
Tags: Python, SSH, Security, Authentication
Read More: /projects/sshield
```

Continue with more cards for all 34 projects...

---

## FIXING FORMATTING ISSUES

### ❌ WRONG (Current Implementation):

```
Text shows:
"## Project Overview ### Problem Statement Network security professionals..."
```

### ✅ CORRECT (New Implementation):

```html
<h2>Project Overview</h2>
<h3>Problem Statement</h3>
<p>Network security professionals need lightweight, customizable tools...</p>
```

**Markdown Rendering Rules:**
1. Parse ALL markdown files to HTML
2. Never show raw markdown symbols (##, *, ---)
3. Use proper HTML tags for headings, lists, emphasis
4. Syntax highlight code blocks
5. Render images properly
6. Format links with proper styling

**Example:**
```javascript
// In your build process
import { marked } from 'marked';

const htmlContent = marked.parse(markdownContent);
// This converts ## to <h2>, ** to <strong>, etc.
```

---

## PROJECT CARDS - ALL 34 GITHUB REPOS

### Featured Projects (Detailed Case Studies)

**1. NetSnoop** - Packet Analyzer
```yaml
category: Offensive/Defensive
image: /images/projects/netsnoop.png
title: NetSnoop - Advanced Packet Analyzer
description: |
  High-performance Python packet sniffer supporting IPv4, IPv6, TCP, UDP, 
  ICMP, DNS, DHCP with real-time analysis and PCAP export.
tech: [Python, Scapy, Matplotlib, Networking]
github: https://github.com/Dynamo2k1/NetSnoop
stars: 4
featured: true
```

**2. CortexCLI** - AI Security Shell
```yaml
category: Development/AI
image: /images/projects/cortexcli.png
title: CortexCLI - AI-Powered Security Shell
description: |
  Linux shell with Google Gemini AI integration, multilingual support, 
  and built-in security filtering to block dangerous commands.
tech: [C, AI, Google Gemini, Security]
github: https://github.com/Dynamo2k1/CortexCLI
stars: 5
featured: true
```

**3. VortexTunnel** - SSH Tunneling
```yaml
category: Offensive
image: /images/projects/vortex.png
title: VortexTunnel - Secure SSH Tunneling Solution
description: |
  Python-based SSH tunneling tool for secure remote access and 
  encrypted communication channels.
tech: [Python, SSH, Networking, Encryption]
github: https://github.com/Dynamo2k1/VortexTunnel
stars: 4
featured: true
```

**4. SSHield** - SSH Security
```yaml
category: Defensive
image: /images/projects/sshield.png
title: SSHield - SSH Security Toolkit
description: |
  Comprehensive Python toolkit for SSH hardening, authentication 
  management, and secure key generation.
tech: [Python, SSH, Security, Authentication]
github: https://github.com/Dynamo2k1/SSHield
stars: 4
featured: true
```

### Additional Projects

**5. SecureDork** - OSINT Tool
```yaml
category: Offensive/OSINT
title: SecureDork - Google Dorking Toolkit
description: Advanced Google dorking tool with GUI for security research and OSINT
tech: [JavaScript, OSINT, Web Security]
github: https://github.com/Dynamo2k1/SecureDork
stars: 4
```

**6. System-Auditor** - Security Auditing
```yaml
category: Defensive
title: System-Auditor - Automated Security Checker
description: C-based tool for system security auditing and vulnerability scanning
tech: [C, Security, System Programming]
github: https://github.com/Dynamo2k1/System-Auditor
stars: 4
```

**7. CyberGuard_agent** - SIEM Agent
```yaml
category: Defensive/SOC
title: CyberGuard Agent - SIEM Log Collector
description: Custom C-based agent for log collection and forwarding to SIEM platforms (developed during NCCS internship)
tech: [C, SIEM, Wazuh, Log Analysis]
github: https://github.com/Dynamo2k1/CyberGuard_agent
stars: 4
highlight: Built during NCCS internship
```

**8. Pipex-Swiss-Army** - Pipeline Tool
```yaml
category: Development
title: Pipex Swiss Army - Pipeline Implementation
description: Multi-purpose pipeline tool for command chaining and automation
tech: [Python, System Programming, Automation]
github: https://github.com/Dynamo2k1/Pipex-Swiss-Army
stars: 4
```

**9. Password-Validator** - Low-level Security
```yaml
category: Development/Security
title: Password Validator - Assembly Language
description: Password strength validator written in Assembly showcasing low-level security programming
tech: [Assembly, Security, Low-level]
github: https://github.com/Dynamo2k1/Password-Validator
stars: 4
highlight: Shows assembly expertise
```

**10. Log_Monitor** - System Monitoring
```yaml
category: Defensive
title: Log Monitor - Real-time Log Analysis
description: Shell-based log monitoring and alerting system for security events
tech: [Bash, Shell, Monitoring, Security]
github: https://github.com/Dynamo2k1/Log_Monitor
stars: 4
```

**11. FastTex** - Rust Project
```yaml
category: Development
title: FastTex - Rust Learning Project
description: Modern systems programming project in Rust for text processing
tech: [Rust, Systems Programming]
github: https://github.com/Dynamo2k1/FastTex
highlight: Learning modern languages
```

**12. FEAS** - Web Application
```yaml
category: Development
title: FEAS - Faculty Evaluation System
description: Web-based faculty evaluation and feedback system
tech: [JavaScript, Web Development]
github: https://github.com/Dynamo2k1/FEAS
stars: 2
```

**13. QEC-FORM-Air-University** - Automation
```yaml
category: Development/Automation
title: QEC Form Automation
description: Python script for automating university quality evaluation forms
tech: [Python, Automation, Web Scraping]
github: https://github.com/Dynamo2k1/QEC-FORM-Air-University
stars: 2
```

**14. Remote-Control-Management-System** - RCMS
```yaml
category: Development/Security
title: RCMS - Remote Management Platform
description: JavaScript-based remote control and management system for secure device administration
tech: [JavaScript, Web, Security]
github: https://github.com/Dynamo2k1/Remote-Control-Management-System
stars: 5
```

**15. Customizeable-Search-Engine**
```yaml
category: Development
title: Custom Search Engine
description: Customizable search engine built with HTML/CSS/JS
tech: [HTML, JavaScript, Web]
github: https://github.com/Dynamo2k1/Customizeable-Search-Engine
stars: 5
```

**16. SIEM_Solution**
```yaml
category: Defensive/SOC
title: SIEM Solution - Security Monitoring
description: Beginner-friendly SIEM implementation for log analysis and threat detection
tech: [JavaScript, Security, SIEM]
github: https://github.com/Dynamo2k1/SIEM_Solution
stars: 3
```

**17. Key_logger** - Educational
```yaml
category: Offensive (Educational)
title: Keylogger - Educational Security Tool
description: Educational keylogger for digital forensics learning (use responsibly)
tech: [C++, Security, Forensics]
github: https://github.com/Dynamo2k1/Key_logger
stars: 4
note: Educational purposes only
```

**18-34. Additional Projects**
Include all remaining repositories from GitHub with similar format.

---

## TECHNICAL IMPLEMENTATION

### Project Structure
```
portfolio/
├── src/
│   ├── components/
│   │   ├── Header.astro              # Fixed header with resume download
│   │   ├── PostCard.astro            # Blog/project card component
│   │   ├── Sidebar.astro             # Sidebar with stats, tags
│   │   ├── TagBadge.astro            # Tag component
│   │   ├── CategoryBadge.astro       # Category badges
│   │   └── Footer.astro              
│   │
│   ├── layouts/
│   │   ├── BaseLayout.astro          # Base with matte black theme
│   │   ├── BlogLayout.astro          # For blog posts
│   │   └── ProjectLayout.astro       # For project pages
│   │
│   ├── pages/
│   │   ├── index.astro               # Blog-style homepage
│   │   ├── blog/
│   │   │   ├── index.astro           # All blog posts
│   │   │   └── [slug].astro          # Individual posts
│   │   ├── projects/
│   │   │   ├── index.astro           # All projects
│   │   │   └── [slug].astro          # Individual projects
│   │   ├── ctf/
│   │   │   ├── index.astro           # CTF writeups
│   │   │   └── [slug].astro          
│   │   ├── tags/
│   │   │   └── [tag].astro           # Filter by tag
│   │   ├── categories/
│   │   │   └── [category].astro      # Filter by category
│   │   ├── about.astro               
│   │   ├── resume.astro              
│   │   └── contact.astro             
│   │
│   ├── content/
│   │   ├── blog/                     # Blog posts (MDX)
│   │   ├── projects/                 # Project pages (Markdown)
│   │   └── ctf/                      # CTF writeups (Markdown)
│   │
│   └── styles/
│       └── global.css                # Matte black theme
│
└── public/
    ├── images/
    │   ├── projects/                 # Project screenshots
    │   ├── blog/                     # Blog images
    │   └── ctf/                      # CTF screenshots
    └── Rana_Uzair_Ahmad_Resume.pdf
```

### Markdown Processing (FIX FORMATTING)

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import remarkGfm from 'remark-gfm';
import rehypePrettyCode from 'rehype-pretty-code';

export default defineConfig({
  integrations: [mdx()],
  markdown: {
    remarkPlugins: [remarkGfm],
    rehypePlugins: [
      [rehypePrettyCode, {
        theme: 'github-dark',
        onVisitLine(node) {
          // Prevent lines from collapsing
          if (node.children.length === 0) {
            node.children = [{ type: 'text', value: ' ' }];
          }
        },
      }],
    ],
    // CRITICAL: Ensure markdown is parsed to HTML
    extendDefaultPlugins: true,
  },
});
```

**Component for Rendering Markdown:**
```astro
---
// PostCard.astro
const { post } = Astro.props;
const { Content } = await post.render(); // Render markdown to HTML
---

<article class="post-card">
  <img src={post.data.image} alt={post.data.title} />
  <div class="post-content">
    <span class="category">{post.data.category}</span>
    <h3>{post.data.title}</h3>
    <!-- Rendered HTML, NOT raw markdown -->
    <div class="description">
      <Content />
    </div>
    <div class="tags">
      {post.data.tags.map(tag => <TagBadge tag={tag} />)}
    </div>
  </div>
</article>
```

---

## STYLING - MATTE BLACK THEME

### Global Styles

```css
/* global.css */

/* Import Tailwind */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Matte Black Theme */
@layer base {
  :root {
    /* Backgrounds */
    --bg-primary: #0d0d0d;
    --bg-secondary: #1a1a1a;
    --bg-elevated: #262626;
    --bg-hover: #303030;
    
    /* Accents */
    --accent-primary: #00ff9f;
    --accent-secondary: #00d4ff;
    
    /* Text */
    --text-primary: #e8e8e8;
    --text-secondary: #a0a0a0;
    --text-heading: #ffffff;
    
    /* Borders */
    --border-subtle: #2a2a2a;
    --border-accent: #00ff9f;
  }
  
  body {
    background-color: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Inter', system-ui, sans-serif;
    line-height: 1.6;
  }
  
  /* Remove default margins */
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  
  /* Headings */
  h1, h2, h3, h4, h5, h6 {
    color: var(--text-heading);
    font-weight: 700;
    line-height: 1.2;
    margin-bottom: 1rem;
  }
  
  h1 { font-size: 2.5rem; }
  h2 { font-size: 2rem; }
  h3 { font-size: 1.5rem; }
  h4 { font-size: 1.25rem; }
  
  /* Links */
  a {
    color: var(--accent-primary);
    text-decoration: none;
    transition: all 200ms ease;
  }
  
  a:hover {
    color: var(--accent-secondary);
  }
  
  /* Code blocks */
  pre {
    background: #1e1e1e;
    padding: 1rem;
    border-radius: 8px;
    overflow-x: auto;
    border: 1px solid var(--border-subtle);
  }
  
  code {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.9em;
  }
  
  /* Inline code */
  :not(pre) > code {
    background: var(--bg-elevated);
    padding: 0.2em 0.4em;
    border-radius: 4px;
    color: var(--accent-primary);
  }
}

/* Post/Project Cards */
@layer components {
  .post-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    overflow: hidden;
    transition: all 300ms ease;
    height: 100%;
    display: flex;
    flex-direction: column;
  }
  
  .post-card:hover {
    transform: translateY(-4px);
    border-color: var(--accent-primary);
    box-shadow: 0 8px 24px rgba(0, 255, 159, 0.1);
  }
  
  .post-card img {
    width: 100%;
    height: 200px;
    object-fit: cover;
  }
  
  .post-content {
    padding: 1.5rem;
    flex: 1;
    display: flex;
    flex-direction: column;
  }
  
  .category {
    display: inline-block;
    background: var(--bg-elevated);
    color: var(--accent-primary);
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }
  
  .post-card h3 {
    color: var(--text-heading);
    font-size: 1.25rem;
    margin-bottom: 0.75rem;
  }
  
  .description {
    color: var(--text-secondary);
    font-size: 0.95rem;
    margin-bottom: 1rem;
    flex: 1;
  }
  
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  
  .tag {
    background: var(--bg-hover);
    color: var(--text-secondary);
    padding: 0.25rem 0.625rem;
    border-radius: 4px;
    font-size: 0.875rem;
  }
  
  /* Buttons */
  .btn-primary {
    background: var(--accent-primary);
    color: #000;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    transition: all 200ms ease;
  }
  
  .btn-primary:hover {
    background: var(--accent-secondary);
    transform: scale(1.05);
    box-shadow: 0 0 20px rgba(0, 255, 159, 0.4);
  }
}
```

---

## HOMEPAGE IMPLEMENTATION

```astro
---
// src/pages/index.astro
import BaseLayout from '../layouts/BaseLayout.astro';
import PostCard from '../components/PostCard.astro';
import Sidebar from '../components/Sidebar.astro';
import { getCollection } from 'astro:content';

// Get all content
const allPosts = await getCollection('blog');
const allProjects = await getCollection('projects');
const allCTF = await getCollection('ctf');

// Combine and sort by date
const allContent = [...allPosts, ...allProjects, ...allCTF]
  .sort((a, b) => b.data.date.valueOf() - a.data.date.valueOf())
  .slice(0, 12); // Latest 12 items
---

<BaseLayout title="Rana Uzair Ahmad | Cybersecurity Engineer">
  <div class="container">
    <!-- Hero Section (Minimal) -->
    <section class="hero">
      <h1>Rana Uzair Ahmad</h1>
      <p class="headline">
        Cybersecurity Engineer | SOC Analyst | Penetration Tester
      </p>
      <p class="subheadline">
        SOC Analyst @ NCCS | Penetration Tester @ ZeroxInnovation<br/>
        Top 4% TryHackMe | 34+ Security Projects
      </p>
      <div class="cta-buttons">
        <a href="/blog" class="btn-primary">View Latest Posts</a>
        <a href="/Rana_Uzair_Ahmad_Resume.pdf" download class="btn-secondary">
          Download Resume
        </a>
      </div>
    </section>
    
    <div class="main-grid">
      <!-- Main Content -->
      <main class="posts-grid">
        <h2>Latest Updates</h2>
        <div class="grid">
          {allContent.map(item => (
            <PostCard post={item} />
          ))}
        </div>
      </main>
      
      <!-- Sidebar -->
      <Sidebar />
    </div>
  </div>
</BaseLayout>

<style>
  .container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
  }
  
  .hero {
    text-align: center;
    padding: 4rem 0;
    border-bottom: 1px solid var(--border-subtle);
    margin-bottom: 3rem;
  }
  
  .hero h1 {
    font-size: 3rem;
    margin-bottom: 1rem;
  }
  
  .headline {
    font-size: 1.5rem;
    color: var(--accent-primary);
    margin-bottom: 0.5rem;
  }
  
  .subheadline {
    color: var(--text-secondary);
    font-size: 1.125rem;
    margin-bottom: 2rem;
  }
  
  .cta-buttons {
    display: flex;
    gap: 1rem;
    justify-content: center;
  }
  
  .main-grid {
    display: grid;
    grid-template-columns: 1fr 350px;
    gap: 2rem;
  }
  
  .posts-grid h2 {
    margin-bottom: 2rem;
  }
  
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 2rem;
  }
  
  @media (max-width: 1024px) {
    .main-grid {
      grid-template-columns: 1fr;
    }
  }
  
  @media (max-width: 768px) {
    .hero h1 {
      font-size: 2rem;
    }
    
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
```

---

## SIDEBAR COMPONENT

```astro
---
// src/components/Sidebar.astro
import { getCollection } from 'astro:content';

const allContent = await getCollection('blog');
const tags = [...new Set(allContent.flatMap(post => post.data.tags))];
const topTags = tags.slice(0, 10); // Top 10 tags
---

<aside class="sidebar">
  <!-- About Me -->
  <div class="sidebar-section">
    <h3>About Me</h3>
    <p>
      SOC Analyst at NCCS and Penetration Tester at ZeroxInnovation. 
      Specializing in threat detection, security tool development, and CTF challenges.
    </p>
    <div class="quick-links">
      <a href="/about">Learn More →</a>
    </div>
  </div>
  
  <!-- Stats -->
  <div class="sidebar-section stats">
    <h3>Stats</h3>
    <div class="stat-item">
      <span class="stat-number">34+</span>
      <span class="stat-label">Projects</span>
    </div>
    <div class="stat-item">
      <span class="stat-number">Top 4%</span>
      <span class="stat-label">TryHackMe</span>
    </div>
    <div class="stat-item">
      <span class="stat-number">Top 900</span>
      <span class="stat-label">HackTheBox</span>
    </div>
  </div>
  
  <!-- Trending Tags -->
  <div class="sidebar-section">
    <h3>Trending Tags</h3>
    <div class="tags-cloud">
      {topTags.map(tag => (
        <a href={`/tags/${tag}`} class="tag">{tag}</a>
      ))}
    </div>
  </div>
  
  <!-- Resume Download -->
  <div class="sidebar-section resume-cta">
    <h3>Get My Resume</h3>
    <a href="/Rana_Uzair_Ahmad_Resume.pdf" download class="btn-download">
      Download PDF
    </a>
  </div>
</aside>

<style>
  .sidebar {
    position: sticky;
    top: 2rem;
  }
  
  .sidebar-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  
  .sidebar-section h3 {
    font-size: 1.125rem;
    margin-bottom: 1rem;
    color: var(--text-heading);
  }
  
  .sidebar-section p {
    color: var(--text-secondary);
    font-size: 0.95rem;
    line-height: 1.6;
  }
  
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
  }
  
  .stat-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
  }
  
  .stat-number {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent-primary);
  }
  
  .stat-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }
  
  .tags-cloud {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  
  .tag {
    background: var(--bg-hover);
    color: var(--text-secondary);
    padding: 0.375rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
    transition: all 200ms ease;
  }
  
  .tag:hover {
    background: var(--accent-primary);
    color: #000;
  }
  
  .resume-cta {
    background: linear-gradient(135deg, var(--bg-secondary), var(--bg-elevated));
    border: 1px solid var(--accent-primary);
  }
  
  .btn-download {
    display: block;
    width: 100%;
    text-align: center;
    background: var(--accent-primary);
    color: #000;
    padding: 0.75rem;
    border-radius: 8px;
    font-weight: 600;
    margin-top: 1rem;
  }
</style>
```

---

## CONTENT EXAMPLES

### Blog Post Example

```markdown
---
# src/content/blog/soc-home-lab.md
title: "Building a Professional SOC Lab with Wazuh and ELK Stack"
description: "Complete guide to setting up enterprise-grade SIEM at home for threat detection practice"
date: 2025-02-01
category: "Tutorial"
tags: ["SIEM", "Wazuh", "ELK", "SOC", "Home Lab"]
image: "/images/blog/soc-lab.png"
author: "Rana Uzair Ahmad"
---

# Building a Professional SOC Lab with Wazuh and ELK Stack

## Introduction

As a SOC Analyst at the National Center of Cyber Security, I work daily with enterprise SIEM platforms. Setting up a home lab helped me practice threat detection and rule creation in a safe environment.

## Hardware Requirements

- **CPU**: 4 cores minimum
- **RAM**: 16GB (32GB recommended)
- **Storage**: 100GB SSD

## Step 1: Setting Up Wazuh

```bash
# Install Wazuh Manager
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-manager
```

## Step 2: Configuring ELK Stack

...continue with proper markdown that will be rendered as HTML...
```

### Project Example

```markdown
---
# src/content/projects/netsnoop.md
title: "NetSnoop - Advanced Packet Analyzer"
description: "High-performance Python packet sniffer supporting 10+ protocols"
date: 2024-10-15
category: "Featured Project"
tags: ["Python", "Scapy", "Networking", "Security"]
image: "/images/projects/netsnoop.png"
github: "https://github.com/Dynamo2k1/NetSnoop"
stars: 4
featured: true
---

# NetSnoop - Advanced Packet Analyzer

## Project Overview

### Problem Statement

Network security professionals need lightweight, customizable tools for packet analysis during penetration testing and security assessments. While Wireshark is industry-standard, there's a need for scriptable, command-line alternatives that integrate into automated workflows.

### Objectives

- Build a high-performance packet analyzer supporting multiple protocols
- Enable real-time capture with custom BPF filtering
- Provide PCAP export compatibility with Wireshark
- Create a tool suitable for both training and professional use

...continue with clean, formatted content...
```

---

## CRITICAL REMINDERS

### ✅ DO THIS:
1. **Matte black background** (#0d0d0d) - ALWAYS
2. **Parse ALL markdown to HTML** - NO raw ## or ** symbols
3. **Blog-style homepage** with cards
4. **All 34 GitHub projects** showcased
5. **Resume download** on every page
6. **Professional positioning** (SOC Analyst + Pentester first)
7. **High contrast text** on black background
8. **Proper spacing** and readability

### ❌ DON'T DO THIS:
1. Blue/navy backgrounds
2. Show markdown symbols (##, **, ---)
3. Traditional portfolio hero layout
4. Student-focused content
5. Neon green/red colors
6. Matrix backgrounds
7. Custom cursors
8. Terminal loaders

---

## DEPLOYMENT

Same as before - deploy to Vercel with matte black theme and blog-style layout.

---

## SUCCESS CRITERIA

The portfolio is successful when:

1. ✅ Background is matte black (#0d0d0d), not blue
2. ✅ No markdown symbols visible anywhere
3. ✅ Homepage shows blog/project cards
4. ✅ All 34 projects are showcased
5. ✅ Resume download on every page
6. ✅ Professional positioning (SOC + Pentester)
7. ✅ Clean, readable formatting
8. ✅ Fast, accessible, SEO-optimized
9. ✅ Lighthouse 90+ scores
10. ✅ Mobile responsive

---

## BEGIN IMPLEMENTATION

Build the portfolio with:
- **Matte black theme** (#0d0d0d background)
- **Blog-style homepage** with content cards
- **Proper markdown rendering** (no visible symbols)
- **All 34 GitHub projects**
- **Resume download everywhere**
- **Professional content** (SOC Analyst + Pentester focus)

Create a modern, unique cybersecurity portfolio that showcases Rana's work in a clean, professional, blog-centric layout with perfect matte black aesthetics.
