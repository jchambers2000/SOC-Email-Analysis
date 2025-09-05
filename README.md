# SOC-Email-Analysis
Hands-on cybersecurity project analyzing malicious emails using open-source tools (VirusTotal, URLScan, AbuseIPDB). Includes SOC-style case reports and documentation.
# SOC Phishing Analysis Project

This repository contains hands-on phishing email investigations designed to simulate the work of a Tier 1 SOC analyst.  
The project focuses on **email triage, header analysis, and IOC enrichment**, using open-source tools and SOC-style reporting.

---

##  Project Overview
The goal of this project is to demonstrate the ability to:
- Collect and analyze suspicious emails
- Extract and review full headers
- Validate SPF, DKIM, and DMARC authentication results
- Perform domain, IP, and URL reputation lookups
- Document findings in **SOC-style case reports**

---

##  Tools & Services Used
- [Google Message Header Analyzer](https://toolbox.googleapps.com/apps/messageheader/)
- [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [VirusTotal](https://www.virustotal.com/)
- [URLScan.io](https://urlscan.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Talos Intelligence](https://talosintelligence.com/reputation_center)

---

##  Repository Structure

- `Reports/` → SOC-style phishing case reports (PDFs or Markdown)
- `Screenshots/` → Redacted screenshots of analysis
- `README.md` → Project overview and documentation

---

## Sample Case Report (Summary)
**Case ID:** PHISH-2025-001  
**Subject:** *Free Bitcoin*  
**Findings:**  
- From: `zasilka@uschovna.cz`  
- Reply-To: `bp1qcej6n9@gmail.com` (mismatch)  
- SPF/DKIM/DMARC: all failed  
- IOC: malicious `.reg` file attachment, suspicious file-sharing URL  
**Assessment:** Phishing / Malware delivery  
**Action Taken:** Blocked sender domain, flagged IOC, documented in report

---

## Resume Highlight
*“Performed phishing email analysis by extracting full headers, validating SPF/DKIM/DMARC, and enriching with VirusTotal, URLScan, and AbuseIPDB lookups; documented results in SOC-style incident reports.”*

---

