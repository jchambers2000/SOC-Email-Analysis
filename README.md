# SOC Email Analysis Portfolio

## Project Overview

This repository documents four independent email investigations completed as a cybersecurity portfolio exercise. The project demonstrates a repeatable Tier 1 SOC analysis process: reviewing message content and metadata, evaluating email authentication, identifying relevant artifacts, enriching infrastructure, and writing evidence-based conclusions.

The collection contains three suspicious investigations and one legitimate Spotify control case. The control case provides a comparison point for normal authentication, sender infrastructure, message content, and reputation observations.

## Investigation Summary

| Case | Classification / verdict | Key supporting findings | Records |
| --- | --- | --- | --- |
| Free Bitcoin | Phishing / Suspected Malicious File Delivery | Cryptocurrency reward lure, an off-domain contact/package-sender address displayed in the message, and an externally hosted 1.2 MB `.reg` package. The package was not collected or analyzed, so malicious behavior is not confirmed. | [Report](<Reports/Case 1 (Free Bitcoin).md>) · [IOC record](<IOCs/Case 1 (Free Bitcoin).md>) |
| Euro Donation | Phishing / Advance-Fee Fraud | Unsolicited €6.5 million donation claim and instructions to respond to an unrelated Gmail address. SPF, DKIM, and DMARC passed; misuse or compromise of the authenticated sender environment remains suspected, not confirmed. | [Report](<Reports/Case 2 (Euro Donation).md>) · [IOC record](<IOCs/Case 2 (Euro Donation).md>) |
| Cedric | Credential Phishing | Unexpected login/reset message, a multi-domain redirect chain, and a cryptocurrency-themed sign-in page. Use of the authenticated sender domain suggests possible compromise, but the repository does not independently confirm it. | [Report](<Reports/Case 3 (Cedric).md>) · [IOC record](<IOCs/Case 3 (Cedric).md>) |
| Spotify Control Case | Legitimate Email | Passing SPF, DKIM, and DMARC results, infrastructure associated with Spotify and Twilio SendGrid, and benign Terms of Use content. No phishing indicator is present in the retained evidence. | [Report](<Reports/Control Case (Spotify).md>) · [Baseline record](<IOCs/Control Case (Spotify).md>) |

The Spotify case is a legitimate comparison baseline, not an IOC collection. It demonstrates why authentication and reputation should be interpreted together with sender context, message content, and requested user action.

## Investigation Methodology

Each case follows the same evidence-focused workflow:

1. Review the visible email content, sender details, subject, timestamps, and available metadata.
2. Compare header-analysis results and evaluate SPF, DKIM, and DMARC without treating authentication as proof of legitimacy.
3. Inspect documented URLs, domains, redirect behavior, and visible file-delivery details.
4. Enrich sending IPs, domains, and URLs using the reputation and infrastructure evidence retained for the case.
5. Record relevant indicators and contextual infrastructure with links to supporting screenshots.
6. Separate direct observations, third-party intelligence output, and analyst assessment.
7. Assign a verdict based on the combined evidence and document unresolved questions and investigation limitations.

## Tools and Techniques

Only tools represented in the retained investigation evidence are listed.

| Tool | Documented use |
| --- | --- |
| Google Message Header Analyzer | Review of message routing and displayed SPF, DKIM, and DMARC results |
| MXToolbox Header Analyzer | Independent header and authentication review |
| VirusTotal | Point-in-time domain and URL reputation observations |
| URLScan | URL, redirect-chain, destination, and landing-page observations |
| AbuseIPDB | Point-in-time sending-IP reputation and infrastructure context |
| Cisco Talos Intelligence | Sender-IP, web-reputation, ownership, and block-list context |

Techniques demonstrated include email metadata review, authentication analysis, IOC extraction, URL defanging, redirect-chain interpretation, infrastructure enrichment, comparison of conflicting tool output, and documentation of analytical uncertainty.

## Repository Structure

```text
SOC-Email-Analysis/
├── Reports/       Professional case reports with findings and limitations
├── IOCs/          Case-specific indicator and baseline records
├── Screenshots/   Redacted supporting evidence organized by case
└── README.md      Portfolio overview and investigation index
```

Reports link directly to their supporting screenshots and IOC or baseline records. Suspicious URLs are defanged in the written documentation.

## Key Skills Demonstrated

- Triaging suspicious email content and identifying common phishing and fraud patterns.
- Interpreting SPF, DKIM, and DMARC results, including conflicting or absent results.
- Distinguishing successful authentication from message legitimacy.
- Correlating sender, domain, URL, IP, redirect, and reputation evidence.
- Separating confirmed observations from suspected compromise and analyst judgment.
- Producing concise case documentation with traceable supporting evidence.
- Applying cautious response recommendations without overgeneralizing domain or IP reputation.

These investigations demonstrate foundational readiness for entry-level SOC email triage and escalation work. They show a structured analytical process, attention to evidence integrity, and an ability to communicate conclusions and limitations without claiming production SOC experience.

## Scope and Limitations

This repository is an independent portfolio exercise. The cases are not production SOC incidents, and the project does not represent enterprise monitoring, containment, remediation, or incident-response actions.

Analysis is limited to the retained emails, screenshots, header-analysis output, and reputation results. Raw `.eml` files and complete raw headers are not retained. No suspicious payload was executed, and no credential submission or endpoint impact was tested.

Third-party reputation results are historical, point-in-time observations. They may change and do not independently prove that an email, domain, URL, or IP address is malicious. Each verdict relies on the combined message, authentication, infrastructure, and behavioral evidence documented in the corresponding report.
