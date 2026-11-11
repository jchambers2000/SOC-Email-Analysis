# Control Case — Spotify

| Field | Value |
| --- | --- |
| Case ID | Control Case (Spotify) |
| Investigation date | 2025-09-03 |
| Classification | Legitimate Email |
| Risk level | None |
| Case role | Legitimate control / comparison baseline |

## Executive Summary

This control case evaluates a Spotify legal-notification email as a baseline for comparison with suspicious messages. The preserved evidence shows passing SPF, DKIM, and DMARC results, sender infrastructure associated with Spotify and Twilio SendGrid, and benign Terms of Use content. No phishing indicator is present in the retained evidence.

## Investigation Scope

The investigation reviewed:

- The preserved email and authentication-summary screenshots.
- SPF, DKIM, and DMARC results displayed by Google.
- Point-in-time VirusTotal and Talos results.
- The visible message content and the URL recorded in the IOC file.

This is a legitimate control case. Its domains, IP address, and URL are contextual baseline indicators, not indicators of compromise.

## Email Metadata

| Field | Observed value |
| --- | --- |
| From | Spotify <no-reply@legal.spotify.com> |
| Recipient | [REDACTED RECIPIENT] |
| Subject | Important Updates to Spotify’s Terms |
| Date | Sep 3, 2025, 4:28 PM |
| Sending IP | 50.31.53.199 |
| Message ID | <Yabh_7ojRtehwgLsMFqefA@geopod-ismtpd-16> |
| Attachment | None observed |

The supplied screenshots do not establish a Reply-To value, so no Reply-To finding is asserted.

## Authentication Analysis

| Control | Direct observation | Interpretation |
| --- | --- | --- |
| SPF | Pass for 50.31.53.199 | The sending IP was authorized by the evaluated SPF policy. |
| DKIM | Pass for spotify.com | The preserved message was signed by spotify.com. |
| DMARC | Pass | The displayed authentication result shows DMARC alignment and a passing result. |

Authentication supports the legitimacy assessment but is not treated as sufficient proof on its own.

## Indicators and Artifacts

| Type | Observable | Role |
| --- | --- | --- |
| Domain | spotify.com | Legitimate control-case domain |
| Domain | legal.spotify.com | Visible sender subdomain |
| IP address | 50.31.53.199 | Sending IP |
| URL | https://www.spotify.com/legal/end-user-agreement/ | URL recorded in the control-case IOC file |

See the [control-case indicator record](<../IOCs/Control Case (Spotify).md>).

## Threat Intelligence Enrichment

These results are third-party, point-in-time observations used as supporting context.

| Source | Target | Result | Evidence |
| --- | --- | --- | --- |
| VirusTotal | spotify.com | 0/98 security vendors flagged the domain | [Screenshot](<../Screenshots/Control Case (Spotify)/virustotal-domain.png>) |
| Talos | 50.31.53.199 | Good sender-IP reputation; hostname o59.em.spotify.com; network owner Twilio SendGrid; BL.SPAMCOP.NET displayed “Listed”; Talos Security Intelligence block list displayed “No” | [Screenshot](<../Screenshots/Control Case (Spotify)/talos-sending-ip.png>) |

No AbuseIPDB screenshot is retained for this control case, so no AbuseIPDB result is asserted.

## Analyst Assessment

### Direct observations

- SPF, DKIM, and DMARC passed.
- The visible From address uses legal.spotify.com.
- The message is a Terms of Use notification and does not request credentials or payment.
- The retained VirusTotal result shows no vendor detections for spotify.com.
- Talos identifies infrastructure associated with Spotify and Twilio SendGrid while also displaying one third-party SpamCop listing.

### Assessment

The aligned authentication results, sender infrastructure, and benign legal-notification content are consistent with legitimate Spotify communications. The retained evidence supports classification as a legitimate email and its use as a comparison baseline.

## Recommended Actions

- No response action is required.
- Retain the case as a baseline when comparing suspicious email content and authentication results.

## Investigation Limitations

- The evidence does not establish a Reply-To header value.
- The email screenshot displays linked text but does not expose every destination URL.
- The Spotify agreement URL is recorded in the IOC file, but the retained screenshot does not independently display its destination.
- No AbuseIPDB result is retained.
- Reputation results reflect the time at which the screenshots were captured and may change.

## Supporting Evidence

- [Email](<../Screenshots/Control Case (Spotify)/email.png>)
- [Email header summary](<../Screenshots/Control Case (Spotify)/email-header-summary.png>)
- [Authentication detail](<../Screenshots/Control Case (Spotify)/authentication-summary.png>)
- [VirusTotal domain result](<../Screenshots/Control Case (Spotify)/virustotal-domain.png>)
- [Talos sending-IP result](<../Screenshots/Control Case (Spotify)/talos-sending-ip.png>)
- [Control-case indicator record](<../IOCs/Control Case (Spotify).md>)
