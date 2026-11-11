# Case 2 — Indicators and Artifacts

| Field | Value |
| --- | --- |
| Case ID | Case 2 (Euro Donation) |
| Investigation date | 2025-08-09 |
| Case classification | Phishing / Advance-Fee Fraud |
| Risk level | Medium |

Defanging is a handling precaution and does not, by itself, assign malicious status.

## Indicator Table

| Indicator type | Defanged indicator value | Observed role | Supporting evidence | Analyst interpretation | Classification |
| --- | --- | --- | --- | --- | --- |
| Email address | francesconnollyf2@gmail[.]com | Off-domain response address shown in the message | [Email](<../Screenshots/Case 2 (Euro Donation)/email.png>) | The message directed the recipient to this address for further instructions. It is directly associated with the advance-fee fraud lure. | Suspicious |
| Domain | munivalpo[.]cl | Authenticated sender domain | [Header summary](<../Screenshots/Case 2 (Euro Donation)/email-header-summary.png>), [Google analysis](<../Screenshots/Case 2 (Euro Donation)/google-header-analysis.png>) | SPF, DKIM, and DMARC passed. The domain is contextual sender infrastructure; compromise or misuse is suspected but not confirmed. | Contextual infrastructure |
| IP address | 200[.]50[.]126[.]100 | Sending IP | [Google analysis](<../Screenshots/Case 2 (Euro Donation)/google-header-analysis.png>), [AbuseIPDB](<../Screenshots/Case 2 (Euro Donation)/abuseipdb-sending-ip.png>), [Talos](<../Screenshots/Case 2 (Euro Donation)/talos-sending-ip.png>) | Observed authenticated sending infrastructure. AbuseIPDB displayed AS15311, hostname mail.munivalpo.cl, ISP Municipalidad de Valparaiso, and Viña del Mar, Valparaiso, Chile. Talos identified Telefonica Empresas Chile SA as the network owner and displayed Valparaiso, Chile. Reputation results were mixed and do not establish domain-wide maliciousness. | Contextual infrastructure |
| Hostname | mail[.]munivalpo[.]cl | Sending mail host | [Google analysis](<../Screenshots/Case 2 (Euro Donation)/google-header-analysis.png>), [Talos](<../Screenshots/Case 2 (Euro Donation)/talos-sending-ip.png>) | Mail host associated with the authenticated sender environment. | Contextual infrastructure |

## Third-Party Reputation Observations

| Source | Evaluated observable | Preserved result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | munivalpo[.]cl | 2/97 vendors flagged the domain | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/virustotal-domain.png>) |
| URLScan | munivalpo[.]cl root | Redirected to the organization's Outlook Web App; no classification | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/urlscan-domain.png>) |
| AbuseIPDB | 200[.]50[.]126[.]100 | Five reports; 15% confidence of abuse | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/abuseipdb-sending-ip.png>) |
| Talos | 200[.]50[.]126[.]100 | Good sender-IP reputation, unknown web reputation, and no displayed active block-list entry | [Screenshot](<../Screenshots/Case 2 (Euro Donation)/talos-sending-ip.png>) |

## Assessment Boundary

The message content and off-domain response address support an advance-fee fraud classification. Authentication establishes that the message used authorized munivalpo.cl infrastructure; it does not establish that the content was legitimate. Compromise or misuse of the sender environment remains suspected and unconfirmed.

See the [full investigation report](<../Reports/Case 2 (Euro Donation).md>).
