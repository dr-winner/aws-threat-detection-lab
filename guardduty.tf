# ─── GuardDuty: managed threat detection ─────────────────────────────────────
# One detector with S3 data-event monitoring. Findings land on the default
# EventBridge bus automatically; detections.tf routes the ones we care about.

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
