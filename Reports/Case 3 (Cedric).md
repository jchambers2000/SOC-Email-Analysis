# Case 3 — Cedric

| Field | Value |
| --- | --- |
| Case ID | Case 3 (Cedric) |
| Investigation date | 2025-09-06 |
| Classification | Credential Phishing |
| Risk level | High |

## Executive Summary

An email presented itself as a login-details notification and included a WordPress password-reset link on cedrichthecarguy.com. A parameter in that link referenced greyxw.blogspot.bg. URLScan evidence shows a multi-domain redirect chain terminating at a cryptocurrency-themed sign-in page on remaskoline.cc.

Use of cedrichthecarguy.com to send the DKIM-signed message and host the password-reset link is consistent with suspected website or mail-environment compromise. The repository does not independently confirm how the infrastructure was accessed or who controlled it.

## Investigation Scope

The investigation reviewed:

- The preserved email and header-analysis screenshots.
- SPF, DKIM, and DMARC results displayed by Google and MXToolbox.
- URLScan results for the sender domain and the URL referenced by the email.
- Point-in-time VirusTotal, AbuseIPDB, and Talos results.
- The redirect chain and landing-page screenshot retained in URLScan evidence.

The password-reset token was redacted during Phase 1. No credential submission, payload execution, domain-owner validation, or hosting-provider response is represented in this repository.

## Email Metadata

| Field | Observed value |
| --- | --- |
| From | contact@cedrichthecarguy.com |
| Recipient | [REDACTED RECIPIENT] |
| Subject | [] Login Details |
| Date | Sep 6, 2025, 4:30 AM CDT |
| Sending IP | 173.231.204.107 |
| Message source | WordPress mailer shown in the preserved header analysis |
| Attachment | None observed |

## Authentication Analysis

| Control | Direct observation | Interpretation |
| --- | --- | --- |
| SPF | None for 173.231.204.107 | This records the observed authentication state. It does not, by itself, establish misconfiguration or compromise. |
| DKIM | Pass for cedrichthecarguy.com | The preserved message was signed by the sender domain. |
| DMARC | MXToolbox reports no DMARC record; Google's summary displays fail | No DMARC record was found. This should not be described as a DMARC policy failure. |

## Indicators and Artifacts

| Type | Observable | Role |
| --- | --- | --- |
| Email address | contact@cedrichthecarguy.com | Authenticated sender |
| Domain | cedrichthecarguy.com | Sender and password-reset host; suspected compromised infrastructure |
| Domain | greyxw.blogspot.bg | Redirector referenced by the message |
| Domain | getk100.cc | Intermediate redirect observed by URLScan |
| Domain | godproxx.cc | Intermediate redirect observed by URLScan |
| Domain | remaskoline.cc | Effective landing domain observed by URLScan |
| URL | hxxp://www[.]greyxw[.]blogspot[.]bg/ | Defanged redirector URL |
| URL | hxxps://cedrichthecarguy[.]com/wp-login.php | Defanged reset URL; token redacted |
| URL | hxxps://remaskoline[.]cc/payouts/ | Defanged effective landing URL |
| IP address | 173.231.204.107 | Sending IP and sender-domain hosting address shown in the evidence |
| IP address | 147.45.198.141 | Main IP for remaskoline.cc shown by URLScan |

See the [Case 3 IOC record](<../IOCs/Case 3 (Cedric).md>).

## Threat Intelligence Enrichment

These results are third-party, point-in-time observations. Provider output is distinguished from the analyst's compromise assessment.

| Source | Target | Result | Evidence |
| --- | --- | --- | --- |
| URLScan | greyxw.blogspot.bg redirect | Redirected through getk100.cc and godproxx.cc to remaskoline.cc/payouts/ at 147.45.198.141; result displayed “Potentially Malicious” and “Malicious Activity” | [Redirect screenshot](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) |
| URLScan | cedrichthecarguy.com | No classification | [Domain screenshot](<../Screenshots/Case 3 (Cedric)/urlscan-sender-domain.png>) |
| VirusTotal | cedrichthecarguy.com | 0/71 vendors flagged the domain; displayed analysis was six years old | [Domain screenshot](<../Screenshots/Case 3 (Cedric)/virustotal-sender-domain.png>) |
| VirusTotal | greyxw.blogspot.bg URL | 1/98 vendors flagged the URL | [URL screenshot](<../Screenshots/Case 3 (Cedric)/virustotal-redirector-url.png>) |
| AbuseIPDB | 173.231.204.107 | Not found in the database; no displayed abuse reports | [Screenshot](<../Screenshots/Case 3 (Cedric)/abuseipdb-sending-ip.png>) |
| Talos | 173.231.204.107 | Neutral sender-IP reputation, unknown web reputation, and no displayed block-list entry | [Screenshot](<../Screenshots/Case 3 (Cedric)/talos-sending-ip.png>) |

No VirusTotal screenshot for remaskoline.cc is retained in the repository.

## Analyst Assessment

### Direct observations

- The message was sent from 173.231.204.107 and DKIM-signed for cedrichthecarguy.com.
- The message contained a WordPress password-reset URL whose parameter referenced greyxw.blogspot.bg.
- URLScan recorded redirects through getk100.cc and godproxx.cc to remaskoline.cc.
- The URLScan landing-page screenshot presents a cryptocurrency-themed sign-in interface.

### Assessment

The unexpected login/reset content, redirect chain, and cryptocurrency-themed sign-in page support a credential-phishing verdict. Use of the authenticated sender domain and its reset functionality suggests possible website or mail-system compromise. That compromise remains an analyst assessment rather than a confirmed incident finding.

## Recommended Actions

- Block or monitor remaskoline.cc and the exact observed landing URL.
- Block or monitor the observed redirector domains with appropriate expiry and review.
- Block or monitor 147.45.198.141 in context with the landing domain.
- Flag contact@cedrichthecarguy.com for validation rather than treating the sender as independently confirmed malicious.
- Escalate suspected compromise to the domain owner or hosting provider for validation.
- Educate users about unexpected password-reset and credential-harvesting messages.

## Investigation Limitations

- No raw .eml file or complete raw header is retained in the repository.
- No VirusTotal result for remaskoline.cc is retained.
- The AbuseIPDB screenshot evaluates the sending IP, not the landing IP.
- No domain-owner, account-owner, or hosting-provider confirmation is available.
- No credential submission or endpoint impact was tested.
- Reputation results reflect the time at which the screenshots were captured and may change.

## Supporting Evidence

- [Email with reset token redacted](<../Screenshots/Case 3 (Cedric)/email.png>)
- [Email header summary](<../Screenshots/Case 3 (Cedric)/email-header-summary.png>)
- [Google header analysis](<../Screenshots/Case 3 (Cedric)/google-header-analysis.png>)
- [MXToolbox header analysis](<../Screenshots/Case 3 (Cedric)/mxtoolbox-header-analysis.png>)
- [URLScan sender-domain result](<../Screenshots/Case 3 (Cedric)/urlscan-sender-domain.png>)
- [URLScan redirect result](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>)
- [VirusTotal sender-domain result](<../Screenshots/Case 3 (Cedric)/virustotal-sender-domain.png>)
- [VirusTotal redirector result](<../Screenshots/Case 3 (Cedric)/virustotal-redirector-url.png>)
- [AbuseIPDB sending-IP result](<../Screenshots/Case 3 (Cedric)/abuseipdb-sending-ip.png>)
- [Talos sending-IP result](<../Screenshots/Case 3 (Cedric)/talos-sending-ip.png>)
- [IOC record](<../IOCs/Case 3 (Cedric).md>)
