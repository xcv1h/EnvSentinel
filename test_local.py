"""Run the handler locally with S3 faked out: python3 test_local.py"""
import io
import json
import sys
import types

fake_boto3 = types.ModuleType("boto3")


class FakeS3:
    def get_object(self, Bucket, Key):
        with open("sample.env", "rb") as f:
            return {"Body": io.BytesIO(f.read())}


fake_boto3.client = lambda name: FakeS3()
sys.modules["boto3"] = fake_boto3

import lambda_function  # noqa: E402

with open("test_event.json") as f:
    event = json.load(f)

result = lambda_function.lambda_handler(event, None)
assert result["status"] == "leak_detected", result
rules = {f["rule"] for f in result["findings"]}
assert {"aws_access_key_id", "aws_secret_access_key", "generic_assignment"} <= rules, rules
assert "wJalr" not in json.dumps(result), "secret leaked into output"
print("OK:", len(result["findings"]), "findings")
