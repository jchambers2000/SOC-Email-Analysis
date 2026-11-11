# Case 1 — Indicators and Artifacts

| Field | Value |
| --- | --- |
| Case ID | Case 1 (Free Bitcoin) |
| Investigation date | 2025-09-01 |
| Case classification | Phishing / Suspected Malicious File Delivery |
| Risk level | High |

Defanging is a handling precaution and does not, by itself, assign malicious status.

## Indicator Table

| Indicator type | Defanged indicator value | Observed role | Supporting evidence | Analyst interpretation | Classification |
| --- | --- | --- | --- | --- | --- |
| URL | hxxps://www[.]uschovna[.]cz/en/zasilka/TNWFE8WBHDI2RME6-83S | Package-delivery URL | [Email](<../Screenshots/Case 1 (Free Bitcoin)/email.png>), [URLScan](<../Screenshots/Case 1 (Free Bitcoin)/urlscan-package-url.png>) | Presented an externally hosted 1.2 MB .reg package through the phishing lure. The package was not analyzed. | Suspicious |
| Email address | bp1qcej6n9@gmail[.]com | Off-domain contact/package-sender address displayed in the message | [Email](<../Screenshots/Case 1 (Free Bitcoin)/email.png>) | The displayed address uses a different domain from the authenticated sender and supports the phishing assessment. The retained evidence does not establish an SMTP Reply-To header value. | Suspicious |
| Domain | uschovna[.]cz | Sender and file-hosting domain | [Email](<../Screenshots/Case 1 (Free Bitcoin)/email.png>), [header summary](<../Screenshots/Case 1 (Free Bitcoin)/email-header-summary.png>) | Legitimate file-hosting infrastructure was used to send the message and host the package. Domain-wide maliciousness is not established. | Contextual infrastructure |
| IP address | 85[.]239[.]227[.]157 | Sending IP | [Header summary](<../Screenshots/Case 1 (Free Bitcoin)/email-header-summary.png>), [AbuseIPDB](<../Screenshots/Case 1 (Free Bitcoin)/abuseipdb-sending-ip.png>), [Talos](<../Screenshots/Case 1 (Free Bitcoin)/talos-sending-ip.png>) | Observed sending infrastructure. AbuseIPDB displayed hostname www301.uschovna.cz, AS15685 (NETHOST s.r.o.), and Prague, Czech Republic. Talos displayed poor sender reputation, while AbuseIPDB evidence was weak and historical. | Contextual / suspicious infrastructure |
| File artifact | 1.2 MB .reg package | Externally hosted file offered to the recipient | [Email](<../Screenshots/Case 1 (Free Bitcoin)/email.png>) | The extension and delivery context are suspicious. Malware behavior is not confirmed because the file was not collected or analyzed. | Suspicious artifact |

## Third-Party Reputation Observations

| Source | Evaluated observable | Preserved result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | uschovna[.]cz | 0/98 vendors flagged the domain | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/virustotal-domain.png>) |
| URLScan | Package page | No classification | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/urlscan-package-url.png>) |
| AbuseIPDB | 85[.]239[.]227[.]157 | One email-spam report from approximately one year earlier; 0% confidence of abuse | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/abuseipdb-sending-ip.png>) |
| Talos | 85[.]239[.]227[.]157 | Poor sender-IP reputation; no displayed block-list entry | [Screenshot](<../Screenshots/Case 1 (Free Bitcoin)/talos-sending-ip.png>) |

## Assessment Boundary

The message is classified as phishing. Malicious file delivery is suspected, but no payload hash, static-analysis result, dynamic-analysis result, or execution evidence is retained.

See the [full investigation report](<../Reports/Case 1 (Free Bitcoin).md>).
