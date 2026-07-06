# ─── Alerting: Lambda formatter → SNS email (+ optional Slack) ───────────────
# The Lambda turns raw EventBridge payloads into a short, readable alert with
# the ATT&CK context from the rule description, then fans out to SNS and, if
# configured, a Slack webhook.

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "archive_file" "alerter" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/alerter.zip"
}

resource "aws_lambda_function" "alerter" {
  function_name    = "${var.project_name}-alerter"
  role             = aws_iam_role.alerter.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  filename         = data.archive_file.alerter.output_path
  source_code_hash = data.archive_file.alerter.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      PROJECT_NAME      = var.project_name
    }
  }
}

resource "aws_cloudwatch_log_group" "alerter" {
  name              = "/aws/lambda/${aws_lambda_function.alerter.function_name}"
  retention_in_days = 30
}

# Least privilege: publish to the one topic, write its own logs. Nothing else.
data "aws_iam_policy_document" "alerter_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "alerter" {
  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid = "WriteLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-alerter:*"]
  }
}

resource "aws_iam_role" "alerter" {
  name               = "${var.project_name}-alerter"
  assume_role_policy = data.aws_iam_policy_document.alerter_assume.json
}

resource "aws_iam_role_policy" "alerter" {
  name   = "alerting"
  role   = aws_iam_role.alerter.id
  policy = data.aws_iam_policy_document.alerter.json
}
