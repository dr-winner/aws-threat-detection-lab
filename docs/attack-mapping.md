# MITRE ATT&CK Mapping

Every detection in this lab maps to a technique in the
[MITRE ATT&CK Cloud (IaaS) matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/).
The EventBridge rule name links the deployed control back to this table.

| Rule | Tactic | Technique | What it catches |
| --- | --- | --- | --- |
| `root-account-activity` | Initial Access / Privilege Escalation | [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | Any API call or console sign-in using root credentials. Root should never be used day-to-day; a single event is actionable. |
| `console-login-no-mfa` | Initial Access | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Successful console sign-in where MFA was not used — credential-stuffing and phished-password logins look exactly like this. |
| `cloudtrail-tampering` | Defense Evasion | [T1562.008 — Impair Defenses: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` — the first thing an intruder does before acting is blind the logs. |
| `iam-persistence` | Persistence | [T1136.003 — Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/), [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) | New IAM users, access keys, login profiles, or directly attached user policies — the classic backdoor after initial compromise. |
| `security-group-exposure` | Defense Evasion | [T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) | Ingress rules opened to `0.0.0.0/0` — accidental exposure and deliberate staging both surface here. |
| `guardduty-findings` | (varies) | GuardDuty's own finding-to-ATT&CK mapping | Managed detections: credential exfiltration, crypto-mining, C2 callbacks, anonymizing proxies, and more, filtered to severity ≥ 4. |

## Coverage honesty

This is a starter detection set, not full coverage. Notable gaps by design
(roadmap material):

- **Exfiltration** (T1537, T1048): needs VPC Flow Logs + traffic baselining.
- **Lateral movement via STS** (T1550.001): needs `AssumeRole` chain analysis.
- **Data destruction** (T1485): needs S3 delete-burst detection with volume thresholds.
- **Defense evasion via region hopping**: the trail is multi-region, but the
  sign-in rules are only complete in `us-east-1` where global console events land.
