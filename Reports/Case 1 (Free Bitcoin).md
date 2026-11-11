# Case 1 — Free Bitcoin

| Field | Value |
| --- | --- |
| Case ID | Case 1 (Free Bitcoin) |
| Investigation date | 2025-09-01 |
| Classification | Phishing / Suspected Malicious File Delivery |
| Risk level | High |

## Executive Summary

An unsolicited email claimed that the recipient had received 2.74 Bitcoin and directed the recipient to an externally hosted package on uschovna.cz. The preserved email screenshot identifies the package as a 1.2 MB .reg file. The lure and delivery method support a phishing classification; malicious file behavior remains suspected because the package was not collected or analyzed.

## Investigation Scope

The investigation reviewed:

- The preserved email and header-analysis screenshots.
- SPF, DKIM, and DMARC results displayed by Google and MXToolbox.
- Point-in-time reputation results from VirusTotal, URLScan, AbuseIPDB, and Talos.
- The externally hosted package details visible in the email.

No payload acquisition, static analysis, dynamic analysis, or execution was performed or retained in this repository.

## Email Metadata

| Field | Observed value |
| --- | --- |
| From | zasilka@uschovna.cz |
| Contact/package-sender address displayed in message | bp1qcej6n9@gmail.com |
| Recipient | [REDACTED RECIPIENT] |
| Subject | Free Bitcoin |
| Date | Sep 1, 2025, 8:40 PM CDT |
| Sending IP | 85.239.227.157 |
| Attachment | None attached to the email |
| External package | 1.2 MB .reg file offered through the hosted URL |

## Authentication Analysis

| Control | Direct observation | Interpretation |
| --- | --- | --- |
| SPF | Pass for 85.239.227.157 | The sending IP was authorized by the evaluated SPF policy. |
| DKIM | Google shows pass for uschovna.cz; MXToolbox shows DKIM alignment but reports authentication failure | The retained analyzers conflict. The repository does not contain enough raw evidence to resolve the discrepancy. |
| DMARC | MXToolbox reports no DMARC record; Google's summary displays fail | No DMARC record was found. This is not, by itself, evidence that the From address was spoofed. |

## Indicators and Artifacts

| Type | Observable | Role |
| --- | --- | --- |
| URL | hxxps://www[.]uschovna[.]cz/en/zasilka/TNWFE8WBHDI2RME6-83S | Defanged package-delivery URL |
| Domain | uschovna.cz | Sender and file-hosting domain |
| IP address | 85.239.227.157 | Sending IP |
| Email address | bp1qcej6n9@gmail.com | Off-domain contact/package-sender address displayed in the message |
| File artifact | 1.2 MB .reg package | Externally hosted, not collected or analyzed |

See the [Case 1 IOC record](<../IOCs/Case 1 (Free Bitcoin).md>).

## Threat Intelligence Enrichment

These results are third-party, point-in-time observations and are not treated as standalone proof of maliciousness.

| Source | Target | Result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | uschovna.cz | 0/98 security vendors flagged the domain | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/virustotal-domain.png>) |
| URLScan | Package page | No classification | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/urlscan-package-url.png>) |
| AbuseIPDB | 85.239.227.157 | One email-spam report from approximately one year earlier; 0% confidence of abuse | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/abuseipdb-sending-ip.png>) |
| Talos | 85.239.227.157 | Poor sender-IP reputation; no displayed block-list entry | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/talos-sending-ip.png>) |

## Analyst Assessment

### Direct observations

- The message used an unsolicited cryptocurrency reward lure.
- The From domain differed from the off-domain contact/package-sender address displayed in the message.
- The recipient was directed to an externally hosted .reg package.
- The authentication tools produced conflicting DKIM results.

### Assessment

The lure, off-domain contact/package-sender address, and externally hosted .reg package are consistent with phishing and suspected malicious file delivery. The evidence supports the phishing verdict but does not independently confirm malware behavior.

## Recommended Actions

- Block or monitor the exact package URL.
- Block or monitor bp1qcej6n9@gmail.com.
- Add the observed URL, sender, and sending IP to detection and hunting queries with case context.
- Validate operational impact before applying domain-wide or IP-wide blocking because uschovna.cz is a file-hosting service.
- Alert users to cryptocurrency-themed phishing lures.

## Investigation Limitations

- The hosted package was not collected, hashed, or analyzed.
- No raw .eml file or complete raw header is retained in the repository.
- The conflicting DKIM results cannot be resolved from the preserved screenshots.
- Reputation results reflect the time at which the screenshots were captured and may change.

## Supporting Evidence

- [Email](<../Screenshots/Case 1 (Free Bitcoin)/email.png>)
- [Email header summary](<../Screenshots/Case 1 (Free Bitcoin)/email-header-summary.png>)
- [Google header analysis](<../Screenshots/Case 1 (Free Bitcoin)/google-header-analysis.png>)
- [MXToolbox header analysis](<../Screenshots/Case 1 (Free Bitcoin)/mxtoolbox-header-analysis.png>)
- [VirusTotal domain result](<../Screenshots/Case 1 (Free Bitcoin)/virustotal-domain.png>)
- [URLScan result](<../Screenshots/Case 1 (Free Bitcoin)/urlscan-package-url.png>)
- [AbuseIPDB result](<../Screenshots/Case 1 (Free Bitcoin)/abuseipdb-sending-ip.png>)
- [Talos result](<../Screenshots/Case 1 (Free Bitcoin)/talos-sending-ip.png>)
- [IOC record](<../IOCs/Case 1 (Free Bitcoin).md>)
