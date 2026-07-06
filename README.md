# AWS Threat Detection Lab

Detection-as-code on AWS: CloudTrail and GuardDuty as telemetry, EventBridge
rules as detection logic mapped to **MITRE ATT&CK**, and a least-privilege
Lambda that turns raw findings into analyst-readable alerts over SNS email
and Slack. One `terraform apply`, one `terraform destroy`, ~zero idle cost.

Built and maintained by [Richard Winner Duvor](https://duvorrichardwinner.me)
— SOC analyst going deep on cloud security. The premise of this repo is the
premise of my career move: **you protect best what you know how to build.**

## Architecture

```
                        ┌──────────────────────────────┐
   management events    │       EventBridge (default)   │
 CloudTrail ───────────▶│                               │
 (multi-region,         │  rules (detections.tf):       │
  log validation,       │   · root-account-activity     │
  S3 + lifecycle)       │   · console-login-no-mfa      │      ┌─────────────┐
                        │   · cloudtrail-tampering      │─────▶│   Lambda    │
 GuardDuty ────────────▶│   · iam-persistence           │      │  formatter  │
 (findings sev ≥ 4,     │   · security-group-exposure   │      └──────┬──────┘
  S3 protection)        │   · guardduty-findings        │             │
                        └──────────────────────────────┘      ┌──────┴──────┐
                                                              ▼             ▼
                                                          SNS email       Slack
```

Every rule carries its ATT&CK technique in the rule description, so the
deployed AWS console *is* the documentation. The full mapping with coverage
notes lives in [`docs/attack-mapping.md`](docs/attack-mapping.md).

## Detections

| Detection | ATT&CK | Why it matters |
| --- | --- | --- |
| Root account activity | T1078.004 | Root use is never routine — one event is actionable |
| Console login without MFA | T1078 | What credential stuffing looks like when it works |
| CloudTrail tampering | T1562.008 | Attackers blind the logs before they act |
| IAM persistence (new users/keys/policies) | T1136.003, T1098 | The classic post-compromise backdoor |
| Security group opened to 0.0.0.0/0 | T1562.007 | Accidental exposure and deliberate staging |
| GuardDuty findings (sev ≥ 4) | varies | Managed coverage: mining, C2, credential exfil |

## Deploy

Prereqs: Terraform ≥ 1.7, AWS credentials with admin on a **lab account**
(never run experiments in an account you care about).

```bash
cp example.tfvars terraform.tfvars   # set alert_email (+ slack webhook if you want)
terraform init
terraform plan
terraform apply
```

Then confirm the SNS subscription email AWS sends you — no confirmation,
no alerts.

## Validate (make it fire)

```bash
# 1. GuardDuty sample findings — end-to-end pipeline test
aws guardduty create-sample-findings \
  --detector-id "$(terraform output -raw guardduty_detector_id)" \
  --finding-types "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"

# 2. IAM persistence — create and immediately delete a canary user
aws iam create-user --user-name detection-lab-canary
aws iam delete-user --user-name detection-lab-canary

# 3. Security group exposure — open and close a canary group
SG=$(aws ec2 create-security-group --group-name detection-lab-canary \
  --description "detection test" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 delete-security-group --group-id "$SG"
```

Each should land in your inbox (and Slack) within a couple of minutes.

## Cost

Designed to idle at ~$0 on a quiet lab account: GuardDuty free for 30 days
(then cents at lab volume), first CloudTrail management trail is free,
EventBridge default-bus rules are free, Lambda/SNS usage is deep inside free
tier, S3 log storage is pennies with the 90-day lifecycle expiry.

## Design choices

- **SSE-S3 over KMS CMK** for the trail bucket: keeps `apply` friction-free
  and free of the CloudTrail↔KMS key-policy dance. Swap in a CMK if you need
  key-level audit; the trade-off is documented in `cloudtrail.tf`.
- **`us-east-1` default**: console sign-in events are global but delivered
  there — the no-MFA and root sign-in rules are most complete in that region.
- **Least-privilege Lambda**: `sns:Publish` on one topic plus its own log
  stream. Nothing else. Read `alerting.tf` — the whole policy fits on a screen.
- **CI as detection hygiene**: `terraform fmt`/`validate`, Checkov IaC scan
  (deliberate skips documented inline), and ruff on the Lambda. Detections
  are code; they get reviewed like code.

## Roadmap

- [ ] VPC Flow Logs + exfiltration detections (T1048, T1537)
- [ ] `AssumeRole` chain analysis for lateral movement (T1550.001)
- [ ] Sigma rule exports of each EventBridge pattern
- [ ] Terratest: apply → trigger canaries → assert alert delivery → destroy
- [ ] Multi-account: org trail + GuardDuty delegated admin

## Teardown

```bash
terraform destroy   # force_destroy on the bucket removes the logs too
```
