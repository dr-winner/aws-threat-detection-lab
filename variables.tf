variable "project_name" {
  description = "Name prefix for every resource in the lab."
  type        = string
  default     = "detection-lab"
}

variable "aws_region" {
  description = "Region to deploy into. Console sign-in events are global but delivered in us-east-1, so the sign-in rules are most complete there."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address subscribed to the SNS alert topic. Confirm the subscription email AWS sends after apply."
  type        = string
}

variable "slack_webhook_url" {
  description = "Optional Slack incoming-webhook URL for alert delivery. Leave empty to use email only."
  type        = string
  default     = ""
  sensitive   = true
}

variable "guardduty_severity_threshold" {
  description = "Minimum GuardDuty finding severity that triggers an alert (GuardDuty scale: 1-10; 4+ = medium, 7+ = high)."
  type        = number
  default     = 4
}

variable "cloudtrail_retention_days" {
  description = "Days to keep CloudTrail logs in S3 before expiry. 90 keeps the lab inside sensible free-tier-ish storage costs."
  type        = number
  default     = 90
}
