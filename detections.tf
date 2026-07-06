# ─── Detections: EventBridge rules mapped to MITRE ATT&CK ───────────────────
# Each rule is a detection-as-code artifact: the event pattern is the logic,
# the description carries the ATT&CK technique, and every rule routes to the
# same alert Lambda. Full mapping table: docs/attack-mapping.md

locals {
  detection_rules = {
    guardduty-findings = {
      description = "GuardDuty finding at or above severity ${var.guardduty_severity_threshold} (ATT&CK: varies per finding type)"
      pattern = jsonencode({
        source      = ["aws.guardduty"]
        detail-type = ["GuardDuty Finding"]
        detail = {
          severity = [{ numeric = [">=", var.guardduty_severity_threshold] }]
        }
      })
    }

    root-account-activity = {
      description = "Any API call made with root credentials — T1078.004 Valid Accounts: Cloud Accounts"
      pattern = jsonencode({
        detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail = {
          userIdentity = {
            type = ["Root"]
          }
        }
      })
    }

    console-login-no-mfa = {
      description = "Successful console sign-in without MFA — T1078 Valid Accounts / T1556.006 MFA modification"
      pattern = jsonencode({
        detail-type = ["AWS Console Sign In via CloudTrail"]
        detail = {
          eventName = ["ConsoleLogin"]
          responseElements = {
            ConsoleLogin = ["Success"]
          }
          additionalEventData = {
            MFAUsed = ["No"]
          }
        }
      })
    }

    cloudtrail-tampering = {
      description = "CloudTrail stopped, deleted, or reconfigured — T1562.008 Impair Defenses: Disable Cloud Logs"
      pattern = jsonencode({
        source      = ["aws.cloudtrail"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["cloudtrail.amazonaws.com"]
          eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
        }
      })
    }

    iam-persistence = {
      description = "New IAM user, access key, or login profile — T1136.003 Create Account / T1098 Account Manipulation"
      pattern = jsonencode({
        source      = ["aws.iam"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName = [
            "CreateUser",
            "CreateAccessKey",
            "CreateLoginProfile",
            "AttachUserPolicy",
            "PutUserPolicy",
          ]
        }
      })
    }

    security-group-exposure = {
      description = "Security group opened to the world — T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
      pattern = jsonencode({
        source      = ["aws.ec2"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress"]
          requestParameters = {
            ipPermissions = {
              items = {
                ipRanges = {
                  items = {
                    cidrIp = ["0.0.0.0/0"]
                  }
                }
              }
            }
          }
        }
      })
    }
  }
}

resource "aws_cloudwatch_event_rule" "detections" {
  for_each = local.detection_rules

  name          = "${var.project_name}-${each.key}"
  description   = each.value.description
  event_pattern = each.value.pattern
}

resource "aws_cloudwatch_event_target" "alert_lambda" {
  for_each = local.detection_rules

  rule = aws_cloudwatch_event_rule.detections[each.key].name
  arn  = aws_lambda_function.alerter.arn
}

resource "aws_lambda_permission" "eventbridge" {
  for_each = local.detection_rules

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detections[each.key].arn
}
