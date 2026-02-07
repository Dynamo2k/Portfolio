export const SITE = {
  title: 'Rana Uzair Ahmad',
  description: 'Cybersecurity professional specializing in SOC operations, penetration testing, and security tool development.',
  url: 'https://dynamo2k1.github.io',
  author: 'Rana Uzair Ahmad',
  headline: 'Cybersecurity Engineer | SOC Analyst | Penetration Tester',
  resumeFile: '/Rana_Uzair_Ahmad_Resume.pdf',
};

export const SOCIAL_LINKS = {
  github: 'https://github.com/Dynamo2k1',
  linkedin: 'https://linkedin.com/in/rana-uzair-ahmad-82b8b6223',
  tryhackme: 'https://tryhackme.com/p/Dynamo2k1',
  hackthebox: 'https://hackthebox.com',
  website: 'https://dynamo2k1.github.io',
  blog: 'https://ciphervanguard.wordpress.com',
  instagram: 'https://www.instagram.com/ra.na_uzair_ahmad/',
  facebook: 'https://www.facebook.com/uzair.ge.56',
  email: 'ranauzair370@gmail.com',
};

export const NAV_LINKS = [
  { label: 'Home', href: '/' },
  { label: 'About', href: '/about/' },
  { label: 'Projects', href: '/projects/' },
  { label: 'Blog', href: '/blog/' },
  { label: 'Resume', href: '/resume/' },
  { label: 'Contact', href: '/contact/' },
];

export const STATS = [
  { label: 'Open Source Projects', value: '34+' },
  { label: 'TryHackMe Ranking', value: 'Top 4%' },
  { label: 'HackTheBox Ranking', value: 'Top 900' },
  { label: 'Years Experience', value: '2+' },
];

export const SKILLS = {
  offensive: {
    title: 'Offensive Security',
    items: ['Penetration Testing', 'Web App Security (OWASP Top 10)', 'Network Penetration Testing', 'Exploit Development', 'Social Engineering', 'Red Team Operations'],
  },
  defensive: {
    title: 'Defensive Security',
    items: ['SOC Operations', 'SIEM (Wazuh, Splunk, ELK)', 'Threat Hunting', 'Incident Response', 'Digital Forensics', 'Malware Analysis', 'Network Monitoring'],
  },
  tools: {
    title: 'Security Tools',
    items: ['Burp Suite', 'Metasploit', 'Nmap', 'Wireshark', 'Volatility', 'Autopsy', 'Ghidra', 'SQLmap', 'John the Ripper', 'Hashcat', 'Zeek', 'Suricata', 'YARA'],
  },
  programming: {
    title: 'Programming',
    items: ['Python', 'C/C++', 'Bash/Shell', 'Assembly', 'Rust', 'JavaScript'],
  },
  frameworks: {
    title: 'Frameworks & Methodologies',
    items: ['MITRE ATT&CK', 'OWASP Testing Guide', 'NIST Framework', 'CIS Controls', 'PTES'],
  },
  os: {
    title: 'Operating Systems',
    items: ['Kali Linux', 'ParrotOS', 'Ubuntu/Debian', 'Windows Internals'],
  },
};

export const EXPERIENCE = [
  {
    title: 'Penetration Tester',
    company: 'ZeroxInnovation',
    period: 'April 2025 - Present',
    description: [
      'Conduct vulnerability assessments and penetration testing for client systems',
      'Identify and exploit security weaknesses in web applications and networks',
      'Provide detailed security reports with remediation recommendations',
    ],
    tech: ['Burp Suite', 'Metasploit', 'Nmap', 'Kali Linux'],
  },
  {
    title: 'SOC Analyst',
    company: 'National Center of Cyber Security',
    period: '2024 - Present',
    description: [
      'Monitor and respond to security incidents using SIEM platforms',
      'Develop custom detection rules for Wazuh and Splunk',
      'Analyze threat patterns and conduct threat hunting',
      'Created C-based security agent for automated log collection',
    ],
    tech: ['Wazuh', 'Splunk', 'Kibana', 'ELK Stack', 'Python', 'C'],
  },
  {
    title: 'Security Intern',
    company: 'National Center of Cyber Security',
    period: 'Jun - Sep 2024',
    description: [
      'Trained on SIEM tools including Wazuh, Splunk, and Kibana',
      'Developed C-based agent for network scanning and log collection',
      'Participated in security operations and incident response',
      'Learned forensic analysis and threat detection techniques',
    ],
    tech: ['Wazuh', 'Splunk', 'Kibana', 'C', 'Linux'],
  },
  {
    title: 'BS Cyber Security',
    company: 'Air University, Islamabad',
    period: '2023 - Present',
    description: [
      'Relevant Coursework: Advanced Cryptography, Network Security, Malware Analysis',
      'Member of Cybersecurity Club and CTF team',
    ],
    tech: [],
  },
];

export const CERTIFICATIONS = [
  { name: 'NCCS Cybercrime and Forensics Lab Internship', year: '2024', file: '/assets/Courses/NCCS.pdf' },
  { name: 'MITRE ATT&CK Framework', year: '2024', file: '/assets/Courses/UC-22a4154a-d60c-482e-9e2c-e1a091c6e86e_MITTRE_ATT&CK.pdf' },
  { name: 'Reverse Engineering & Malware Analysis (REMASM+)', year: '2024', file: '/assets/Courses/UC-72c6266e-95d0-4ae9-8ff1-d2555358e590_malware.pdf' },
  { name: 'OSCP Preparation Series - Part 1', year: '2024', file: '/assets/Courses/UC-384f711d-180e-4e8a-9c5c-c7db00efdadd.pdf' },
  { name: 'OSCP Preparation Series - Part 2', year: '2024', file: '/assets/Courses/UC-5e9d078d-825b-485f-a30b-3ad23be5026b_OSCP2.pdf' },
  { name: 'OSCP Preparation Series - Part 3', year: '2024', file: '/assets/Courses/UC-cd1ee934-535d-43f5-ac2a-5759304226ad_OSCP3.pdf' },
  { name: 'x64dbg Static Analysis', year: '2024', file: '/assets/Courses/UC-c21eea3d-ecc9-415c-a3a5-35e14a014677_autospy.pdf' },
  { name: 'TryHackMe Advent of Cyber 2024', year: '2024', file: '/assets/Courses/THM-ZN3UO9BTNL.pdf' },
  { name: 'Wireshark Analysis', year: '2024', file: '/assets/Courses/UC-d6a5751e-40ce-43f6-a986-ea0cd7017cfb_shark.pdf' },
];

export const FEATURED_PROJECTS = [
  {
    name: 'NetSnoop',
    slug: 'netsnoop',
    tagline: 'Advanced Packet Analyzer for Network Security',
    description: 'A Python-based packet analyzer built with Scapy for real-time network traffic capture and analysis. Supports multi-protocol dissection, BPF filtering, and PCAP export.',
    tech: ['Python', 'Scapy', 'Matplotlib'],
    category: 'offensive',
    github: 'https://github.com/Dynamo2k1/NetSnoop',
    stars: 4,
    image: '/images/projects/Net_Snoop.png',
    featured: true,
  },
  {
    name: 'CortexCLI',
    slug: 'cortexcli',
    tagline: 'AI-Powered Security Shell',
    description: 'An AI-integrated command-line security tool written in C that leverages artificial intelligence for enhanced security operations and threat analysis.',
    tech: ['C', 'AI Integration'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/CortexCLI',
    stars: 0,
    image: '/images/projects/CortexCLI.png',
    featured: true,
  },
  {
    name: 'VortexTunnel',
    slug: 'vortextunnel',
    tagline: 'SSH Tunneling Solution',
    description: 'A Python-based SSH tunneling tool for creating secure, encrypted communication channels. Features multiple tunneling modes and easy configuration.',
    tech: ['Python', 'SSH', 'Networking'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/VortexTunnel',
    stars: 0,
    image: '/images/projects/Vortex.png',
    featured: true,
  },
  {
    name: 'SSHield',
    slug: 'sshield',
    tagline: 'SSH Security Toolkit',
    description: 'A comprehensive SSH security toolkit in Python for hardening SSH configurations, monitoring access, and detecting brute-force attacks.',
    tech: ['Python', 'SSH', 'Security'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/SSHield',
    stars: 4,
    image: '/images/projects/Pipex.png',
    featured: true,
  },
  {
    name: 'SecureDork',
    slug: 'securedork',
    tagline: 'Google Dorking Tool',
    description: 'An automated Google dorking tool for reconnaissance during penetration testing. Generates and executes targeted search queries to discover exposed information.',
    tech: ['JavaScript', 'Web Scraping'],
    category: 'offensive',
    github: 'https://github.com/Dynamo2k1/SecureDork',
    stars: 4,
    forks: 2,
    featured: true,
  },
  {
    name: 'System-Auditor',
    slug: 'system-auditor',
    tagline: 'Security Auditing Tool',
    description: 'A C-based system auditing tool for comprehensive security assessments. Performs automated checks on system configurations, permissions, and vulnerabilities.',
    tech: ['C', 'Linux', 'Security'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/System-Auditor',
    stars: 4,
    featured: true,
  },
  {
    name: 'CyberGuard_agent',
    slug: 'cyberguard-agent',
    tagline: 'SIEM Agent for Log Collection',
    description: 'A C-based SIEM agent developed during NCCS internship. Handles automated log collection, network scanning, and security event forwarding.',
    tech: ['C', 'SIEM', 'Networking'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/CyberGuard_agent',
    stars: 4,
    featured: true,
  },
  {
    name: 'Pipex-Swiss-Army',
    slug: 'pipex-swiss-army',
    tagline: 'Pipeline Implementation',
    description: 'A versatile pipeline implementation in Python for data processing and automation tasks. Features modular design and extensible architecture.',
    tech: ['Python', 'Automation'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/Pipex-Swiss-Army',
    stars: 4,
    forks: 1,
    featured: true,
  },
];

export const ADDITIONAL_PROJECTS = [
  {
    name: 'Password-Validator',
    description: 'Password validation tool written in Assembly language, demonstrating low-level programming expertise.',
    tech: ['Assembly'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/Password-Validator',
  },
  {
    name: 'Log_Monitor',
    description: 'System log monitoring tool built with Shell scripting for real-time security event tracking.',
    tech: ['Shell'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/Log_Monitor',
    stars: 4,
  },
  {
    name: 'FastTex',
    description: 'A Rust-based project showcasing modern systems programming for high-performance applications.',
    tech: ['Rust'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/FastTex',
  },
  {
    name: 'FEAS',
    description: 'Faculty Evaluation Automation System for streamlining academic evaluation processes.',
    tech: ['JavaScript'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/FEAS',
    stars: 2,
    forks: 1,
  },
  {
    name: 'QEC-FORM-Air-University',
    description: 'Automated form filling solution for Air University QEC evaluations.',
    tech: ['Python'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/QEC-FORM-Air-University',
    stars: 2,
  },
  {
    name: 'Remote-Control-Management-System',
    description: 'A remote control management system for centralized device administration and monitoring.',
    tech: ['JavaScript'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/Remote-Control-Management-System',
    stars: 5,
  },
  {
    name: 'Customizeable-Search-Engine',
    description: 'A customizable search engine interface with advanced filtering and search capabilities.',
    tech: ['HTML', 'JavaScript'],
    category: 'development',
    github: 'https://github.com/Dynamo2k1/Customizeable-Search-Engine',
    stars: 5,
    forks: 1,
  },
  {
    name: 'SIEM_Solution',
    description: 'A complete SIEM solution for security information and event management.',
    tech: ['JavaScript'],
    category: 'defensive',
    github: 'https://github.com/Dynamo2k1/SIEM_Solution',
    stars: 3,
  },
  {
    name: 'Key_logger',
    description: 'Educational keylogger implementation for understanding input capture techniques. For security research purposes only.',
    tech: ['C++'],
    category: 'research',
    github: 'https://github.com/Dynamo2k1/Key_logger',
    stars: 4,
  },
];

export const CTF_ACHIEVEMENTS = [
  {
    platform: 'TryHackMe',
    achievement: 'Top 4% Globally',
    details: '70+ rooms completed, 100% Offensive Path completion',
    link: 'https://tryhackme.com/p/Dynamo2k1',
  },
  {
    platform: 'HackTheBox',
    achievement: 'Top 900 Ranking',
    details: 'Active participant and challenger',
    link: 'https://hackthebox.com',
  },
  {
    platform: 'CTFtime',
    achievement: 'Top 7 Ranking',
    details: 'Consistent competitive performance',
    link: 'https://ctftime.org',
  },
];

export const COMPETITION_WINS = [
  '1st Place - Air University CTF (2024)',
  '2nd Place - Islamabad Cyber Challenge',
  'Best Pentester - Cyber Youth Competition',
];
