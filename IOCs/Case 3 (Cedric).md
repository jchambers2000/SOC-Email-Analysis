# Case 3 — Indicators and Artifacts

| Field | Value |
| --- | --- |
| Case ID | Case 3 (Cedric) |
| Investigation date | 2025-09-06 |
| Case classification | Credential Phishing |
| Risk level | High |

Defanging is a handling precaution and does not, by itself, assign malicious status.

## Indicator Table

| Indicator type | Defanged indicator value | Observed role | Supporting evidence | Analyst interpretation | Classification |
| --- | --- | --- | --- | --- | --- |
| Email address | contact@cedrichthecarguy[.]com | Authenticated sender | [Email](<../Screenshots/Case 3 (Cedric)/email.png>), [header summary](<../Screenshots/Case 3 (Cedric)/email-header-summary.png>) | Sender associated with the domain used for the signed message and reset link. Treat as suspected compromised context, not an independently confirmed malicious identity. | Contextual / suspected compromised sender |
| Domain | cedrichthecarguy[.]com | Sender and password-reset host | [Email](<../Screenshots/Case 3 (Cedric)/email.png>), [URLScan](<../Screenshots/Case 3 (Cedric)/urlscan-sender-domain.png>) | The domain appears to host a legitimate business website. Its use in the phishing chain suggests possible compromise, which is not independently confirmed. | Contextual / suspected compromised infrastructure |
| Domain | greyxw[.]blogspot[.]bg | Redirector referenced in the message | [Email](<../Screenshots/Case 3 (Cedric)/email.png>), [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Initial redirector associated with the phishing path. | Suspicious redirector |
| Domain | getk100[.]cc | Intermediate redirect | [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Observed by URLScan between the initial redirector and landing domain. | Suspicious redirect infrastructure |
| Domain | godproxx[.]cc | Intermediate redirect | [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Observed by URLScan between the initial redirector and landing domain. | Suspicious redirect infrastructure |
| Domain | remaskoline[.]cc | Effective landing domain | [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Hosted the cryptocurrency-themed sign-in page reached by the redirect chain. | Suspicious phishing landing host |
| URL | hxxp://www[.]greyxw[.]blogspot[.]bg/ | Initial redirector URL | [Email](<../Screenshots/Case 3 (Cedric)/email.png>), [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Defanged URL associated with the observed phishing path. | Suspicious |
| URL | hxxps://cedrichthecarguy[.]com/wp-login.php | WordPress reset URL | [Email](<../Screenshots/Case 3 (Cedric)/email.png>) | The reset link contained the Blogspot value as a parameter; its token is redacted. The repository does not establish whether this URL was followed. | Suspicious use of contextual infrastructure |
| URL | hxxps://remaskoline[.]cc/payouts/ | Effective landing URL | [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Displayed a cryptocurrency-themed sign-in interface. | Suspicious phishing landing URL |
| IP address | 173[.]231[.]204[.]107 | Sending IP and sender-domain hosting address | [Google analysis](<../Screenshots/Case 3 (Cedric)/google-header-analysis.png>), [AbuseIPDB](<../Screenshots/Case 3 (Cedric)/abuseipdb-sending-ip.png>), [Talos](<../Screenshots/Case 3 (Cedric)/talos-sending-ip.png>) | Contextual infrastructure associated with the authenticated sender domain. The retained evidence identifies InMotion Hosting and hostname vps99555.inmotionhosting.com. AbuseIPDB did not show reports. | Contextual infrastructure |
| IP address | 147[.]45[.]198[.]141 | Main IP for remaskoline.cc | [URLScan redirect chain](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) | Hosting address for the observed phishing landing domain. URLScan identified Hostinux Limited and Germany. | Suspicious landing infrastructure |

## Third-Party Reputation Observations

| Source | Evaluated observable | Preserved result | Evidence |
| --- | --- | --- | --- |
| URLScan | greyxw[.]blogspot[.]bg redirect | Redirected through getk100.cc and godproxx.cc to remaskoline.cc/payouts/ at 147.45.198.141; displayed “Potentially Malicious” and “Malicious Activity” | [Screenshot](<../Screenshots/Case 3 (Cedric)/urlscan-redirect-chain.png>) |
| URLScan | cedrichthecarguy[.]com | No classification | [Screenshot](<../Screenshots/Case 3 (Cedric)/urlscan-sender-domain.png>) |
| VirusTotal | cedrichthecarguy[.]com | 0/71 vendors flagged the domain; displayed analysis was six years old | [Screenshot](<../Screenshots/Case 3 (Cedric)/virustotal-sender-domain.png>) |
| VirusTotal | greyxw[.]blogspot[.]bg URL | 1/98 vendors flagged the URL | [Screenshot](<../Screenshots/Case 3 (Cedric)/virustotal-redirector-url.png>) |
| AbuseIPDB | 173[.]231[.]204[.]107 | Not found in the database; no displayed abuse reports | [Screenshot](<../Screenshots/Case 3 (Cedric)/abuseipdb-sending-ip.png>) |
| Talos | 173[.]231[.]204[.]107 | Neutral sender-IP reputation, unknown web reputation, and no displayed block-list entry | [Screenshot](<../Screenshots/Case 3 (Cedric)/talos-sending-ip.png>) |

No VirusTotal screenshot for remaskoline.cc is retained. The AbuseIPDB evidence evaluates the sending IP, not the landing IP.

## Assessment Boundary

The observed redirect chain and cryptocurrency-themed sign-in page support the credential-phishing verdict. Compromise of cedrichthecarguy.com is suspected but not independently confirmed by domain-owner, account-owner, or hosting-provider evidence.

See the [full investigation report](<../Reports/Case 3 (Cedric).md>).
