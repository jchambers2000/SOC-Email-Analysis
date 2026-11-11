# Case 2 — Euro Donation

| Field | Value |
| --- | --- |
| Case ID | Case 2 (Euro Donation) |
| Investigation date | 2025-08-09 |
| Classification | Phishing / Advance-Fee Fraud |
| Risk level | Medium |

## Executive Summary

An authenticated email claimed that the recipient had been selected to receive a €6,500,000 donation and directed the recipient to respond to an unrelated Gmail address. The message content and off-domain response address support an advance-fee fraud classification even though SPF, DKIM, and DMARC passed.

## Investigation Scope

The investigation reviewed:

- The preserved email and header-analysis screenshots.
- SPF, DKIM, and DMARC results displayed by Google and MXToolbox.
- Point-in-time reputation results from VirusTotal, URLScan, AbuseIPDB, and Talos.
- The message content and response address shown in the email.

The repository does not include account-owner confirmation, sender-environment logs, or evidence establishing how the authenticated infrastructure was used.

## Email Metadata

| Field | Observed value |
| --- | --- |
| From | [REDACTED SENDER]@munivalpo.cl |
| Response address shown in message | francesconnollyf2@gmail.com |
| Recipient | [REDACTED RECIPIENT] |
| Subject | RE |
| Date | Aug 9, 2025, 11:19 AM CDT |
| Sending IP | 200.50.126.100 |
| Hostname | mail.munivalpo.cl |
| ASN | AS15311 — TELEFONICA EMPRESAS CHILE SA |
| Country | Chile |
| Attachment | None observed |

The preserved evidence shows the Gmail address in the message body. It does not independently establish that the address was set as the SMTP Reply-To header.

## Authentication Analysis

| Control | Direct observation | Interpretation |
| --- | --- | --- |
| SPF | Pass for 200.50.126.100 | The sending IP was authorized by the evaluated SPF policy. |
| DKIM | Pass for munivalpo.cl | The preserved message was signed by the sender domain. |
| DMARC | Pass | The displayed authentication results show DMARC alignment and a passing result. |

Successful authentication establishes domain authorization and alignment; it does not establish that the message content is legitimate.

## Indicators and Artifacts

| Type | Observable | Role |
| --- | --- | --- |
| Email address | francesconnollyf2@gmail.com | Off-domain response address used by the fraud lure |
| Domain | munivalpo.cl | Authenticated sender domain |
| IP address | 200.50.126.100 | Sending IP |
| Hostname | mail.munivalpo.cl | Sending mail host |

See the [Case 2 IOC record](<../IOCs/Case 2 (Euro Donation).md>).

## Threat Intelligence Enrichment

These results are third-party, point-in-time observations and are not treated as standalone proof that the entire sender domain is malicious.

| Source | Target | Result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | munivalpo.cl | 2/97 security vendors flagged the domain | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/virustotal-domain.png>) |
| URLScan | munivalpo.cl root | Redirected to the organization's Outlook Web App; no classification | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/urlscan-domain.png>) |
| AbuseIPDB | 200.50.126.100 | Five reports; 15% confidence of abuse | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/abuseipdb-sending-ip.png>) |
| Talos | 200.50.126.100 | Good sender-IP reputation, unknown web reputation, and no displayed active block-list entry | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/talos-sending-ip.png>) |

## Analyst Assessment

### Direct observations

- The message promised an unsolicited €6.5 million donation.
- The message directed the recipient to an unrelated Gmail address.
- SPF, DKIM, and DMARC passed.
- No attachment was observed.

### Assessment

The content and response address establish an advance-fee fraud attempt despite successful email authentication. Misuse of or compromise within legitimate infrastructure is suspected because the message authenticated as munivalpo.cl and traversed the organization's mail infrastructure. The repository does not contain evidence that independently confirms compromise.

## Recommended Actions

- Block or monitor francesconnollyf2@gmail.com.
- Escalate the authenticated sender and infrastructure for compromise validation.
- Avoid blocking the entire municipal domain solely on the basis of this message.
- Train users on donation and advance-fee fraud lures.
- Combine From/response-address mismatch with content or other signals in detection logic; a mismatch alone can occur in legitimate email.

## Investigation Limitations

- The evidence does not establish an SMTP Reply-To header value.
- No raw .eml file or complete raw header is retained in the repository.
- No account-owner confirmation or sender-environment logs are available.
- The URLScan screenshot evaluates the domain root and its Outlook Web App, not a link delivered in the email body.
- Reputation results reflect the time at which the screenshots were captured and may change.

## Supporting Evidence

- [Email](<../Screenshots/Case 2 (Euro Donation)/email.png>)
- [Email header summary](<../Screenshots/Case 2 (Euro Donation)/email-header-summary.png>)
- [Google header analysis](<../Screenshots/Case 2 (Euro Donation)/google-header-analysis.png>)
- [MXToolbox header analysis](<../Screenshots/Case 2 (Euro Donation)/mxtoolbox-header-analysis.png>)
- [VirusTotal domain result](<../Screenshots/Case 2 (Euro Donation)/virustotal-domain.png>)
- [URLScan result](<../Screenshots/Case 2 (Euro Donation)/urlscan-domain.png>)
- [AbuseIPDB result](<../Screenshots/Case 2 (Euro Donation)/abuseipdb-sending-ip.png>)
- [Talos result](<../Screenshots/Case 2 (Euro Donation)/talos-sending-ip.png>)
- [IOC record](<../IOCs/Case 2 (Euro Donation).md>)
