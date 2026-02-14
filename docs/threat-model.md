# Threat Model

## 1. Purpose

This application is a local security auditing tool.  
Its purpose is to scan and report potential security gaps on a personal computer.

It does not provide active protection, real-time monitoring, intrusion detection, or automated mitigation.

The tool performs analysis only and generates reports based on system state at the time of execution.

---

## 2. Target Audience

This tool is intended for individual PC users who want visibility into potential local security weaknesses without modifying system configurations.

It may also be used for educational or research purposes.

---

## 3. Scope of Analysis

The tool analyzes:

- Open network ports and exposed services
- Firewall status and configuration overview
- Connected USB devices and related risks
- Application update status (outdated software detection)
- Potential unauthorized access to camera and microphone
- Indicators of external data transmission

The analysis is limited to accessible user-level system information.

---

## 4. Non-Goals

This tool does NOT:

- Provide antivirus or anti-malware protection
- Monitor systems in real time
- Block traffic or enforce firewall rules
- Automatically fix or patch vulnerabilities
- Perform penetration testing
- Detect kernel-level or zero-day exploits

---

## 5. Risk Classification

Findings are categorized as:

- Low
- Medium
- High
- Critical

Risk levels are determined based on exposure level, potential impact, and likelihood of misuse.

---

## 6. Limitations

- Results reflect system state only at scan time
- Detection accuracy depends on operating system permissions
- Some findings may generate false positives
- Deep system or kernel-level inspection is out of scope
- Network traffic inspection is limited to observable metadata, not full packet analysis
