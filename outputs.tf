output "cloudtrail_bucket" {
  description = "S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.trail.id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID (use with `aws guardduty create-sample-findings`)."
  value       = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  description = "Alert topic — confirm the email subscription after first apply."
  value       = aws_sns_topic.alerts.arn
}

output "detection_rules" {
  description = "Deployed EventBridge detection rules."
  value       = [for r in aws_cloudwatch_event_rule.detections : r.name]
}
