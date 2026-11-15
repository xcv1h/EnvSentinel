"""EnvSentinel PoC: scan an S3 object for leaked secrets.

Triggered by an EventBridge rule on S3 "Object Created" events.
Findings go to CloudWatch Logs as one JSON line per invocation.
"""
import json
import re

import boto3

s3 = boto3.client("s3")

MAX_BYTES = 1_000_000  # skip anything bigger than ~1 MB

PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_access_key": re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "generic_assignment": re.compile(
        r"(?i)(?:password|passwd|secret|api_?key|token)\w*\s*[=:]\s*['\"]?([^\s'\"]{8,})"
    ),
}


def mask(value):
    """Never log the secret itself, only enough to recognise it."""
    return value[:4] + "*" * 8


def scan(text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        hits = []
        for rule, pattern in PATTERNS.items():
            match = pattern.search(line)
            if not match:
                continue
            secret = match.group(1) if match.groups() else match.group(0)
            hits.append({"rule": rule, "line": lineno, "match": mask(secret)})
        # the generic rule is a fallback: drop it when a specific rule hit
        if len(hits) > 1:
            hits = [h for h in hits if h["rule"] != "generic_assignment"]
        findings.extend(hits)
    return findings


def lambda_handler(event, context):
    detail = event["detail"]
    bucket = detail["bucket"]["name"]
    key = detail["object"]["key"]
    size = detail["object"].get("size", 0)

    result = {"bucket": bucket, "key": key, "size": size}

    if size > MAX_BYTES:
        result["status"] = "skipped_too_large"
    else:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        findings = scan(body.decode("utf-8", errors="replace"))
        result["status"] = "leak_detected" if findings else "clean"
        result["findings"] = findings

    print(json.dumps(result))
    return result
