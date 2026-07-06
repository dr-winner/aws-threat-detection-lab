"""Alert formatter: EventBridge detection events -> SNS email + optional Slack.

Keeps the output terse and analyst-readable: what fired, who did it, from
where, and the ATT&CK context carried on the EventBridge rule description.
"""

import json
import os
import urllib.request

import boto3

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "detection-lab")

sns = boto3.client("sns")


def _guardduty_summary(detail: dict) -> dict:
    service = detail.get("service", {})
    return {
        "finding": detail.get("type", "unknown"),
        "severity": detail.get("severity"),
        "title": detail.get("title", ""),
        "account": detail.get("accountId", ""),
        "region": detail.get("region", ""),
        "first_seen": service.get("eventFirstSeen", ""),
        "count": service.get("count", 1),
    }


def _cloudtrail_summary(detail: dict) -> dict:
    identity = detail.get("userIdentity", {})
    return {
        "event": detail.get("eventName", "unknown"),
        "actor": identity.get("arn") or identity.get("type", "unknown"),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": (detail.get("userAgent") or "")[:120],
        "region": detail.get("awsRegion", ""),
        "time": detail.get("eventTime", ""),
        "mfa": (detail.get("additionalEventData") or {}).get("MFAUsed", "n/a"),
    }


def _format(event: dict) -> tuple[str, str]:
    detail_type = event.get("detail-type", "Unknown event")
    detail = event.get("detail", {})

    if detail_type == "GuardDuty Finding":
        summary = _guardduty_summary(detail)
        subject = f"[{PROJECT_NAME}] GuardDuty sev {summary['severity']}: {summary['finding']}"
    else:
        summary = _cloudtrail_summary(detail)
        subject = f"[{PROJECT_NAME}] {detail_type}: {summary['event']} by {summary['actor']}"

    lines = [f"{k}: {v}" for k, v in summary.items() if v not in ("", None)]
    body = "\n".join([subject, "-" * len(subject), *lines])
    # SNS email subjects are capped at 100 chars
    return subject[:100], body


def _post_slack(subject: str, body: str) -> None:
    payload = json.dumps(
        {"text": f"*{subject}*\n```{body}```"}
    ).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=5)


def lambda_handler(event, _context):
    subject, body = _format(event)

    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)

    if SLACK_WEBHOOK_URL:
        try:
            _post_slack(subject, body)
        except Exception as exc:  # Slack is best-effort; SNS already delivered
            print(f"slack delivery failed: {exc}")

    return {"ok": True, "subject": subject}
