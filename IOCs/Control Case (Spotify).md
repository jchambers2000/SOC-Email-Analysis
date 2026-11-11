# Spotify Control Case — Legitimate Baseline Observations

| Field | Value |
| --- | --- |
| Case ID | Control Case (Spotify) |
| Investigation date | 2025-09-03 |
| Case classification | Legitimate Email |
| Risk level | None |
| Record type | Legitimate baseline observations |

The values below are retained for comparison with suspicious investigations. They are not indicators of compromise. Defanging is used for consistent handling and does not imply malicious status.

## Baseline Indicator Table

| Indicator type | Defanged indicator value | Observed role | Supporting evidence | Analyst interpretation | Classification |
| --- | --- | --- | --- | --- | --- |
| Domain | spotify[.]com | Legitimate organizational domain | [Email](<../Screenshots/Control Case (Spotify)/email.png>), [VirusTotal](<../Screenshots/Control Case (Spotify)/virustotal-domain.png>) | Domain associated with the legitimate control message and the DKIM signature. | Legitimate baseline |
| Domain | legal[.]spotify[.]com | Visible sender subdomain | [Email](<../Screenshots/Control Case (Spotify)/email.png>), [header summary](<../Screenshots/Control Case (Spotify)/email-header-summary.png>) | Sender subdomain displayed in the preserved message. | Legitimate baseline |
| IP address | 50[.]31[.]53[.]199 | Sending IP | [Header summary](<../Screenshots/Control Case (Spotify)/email-header-summary.png>), [Talos](<../Screenshots/Control Case (Spotify)/talos-sending-ip.png>) | Authenticated sending infrastructure associated with Spotify and Twilio SendGrid in the retained evidence. | Legitimate baseline |
| URL | hxxps://www[.]spotify[.]com/legal/end-user-agreement/ | Agreement URL recorded in the original control record | [Email](<../Screenshots/Control Case (Spotify)/email.png>) | Contextual URL retained from the original record. The screenshot displays linked text but does not independently expose this destination. | Legitimate baseline / destination not independently verified |

## Third-Party Reputation Observations

| Source | Evaluated observable | Preserved result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | spotify[.]com | 0/98 vendors flagged the domain | [Screenshot](<../Screenshots/Control Case (Spotify)/virustotal-domain.png>) |
| Talos | 50[.]31[.]53[.]199 | Good sender-IP reputation; hostname o59.em.spotify.com; network owner Twilio SendGrid; BL.SPAMCOP.NET displayed “Listed”; Talos Security Intelligence block list displayed “No” | [Screenshot](<../Screenshots/Control Case (Spotify)/talos-sending-ip.png>) |

No AbuseIPDB screenshot is retained, so no AbuseIPDB result is asserted.

## Assessment Boundary

The passing authentication results, sender infrastructure, and benign legal-notification content support classification as a legitimate email. These baseline observations must not be imported into block lists or treated as malicious IOCs.

See the [full control-case report](<../Reports/Control Case (Spotify).md>).
