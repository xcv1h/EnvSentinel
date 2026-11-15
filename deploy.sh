#!/usr/bin/env bash
# EnvSentinel PoC deploy. Needs AWS CLI v2 with credentials configured.
# Usage: BUCKET=envsentinel-poc-yourname ./deploy.sh
set -euo pipefail

BUCKET="${BUCKET:?set BUCKET to a globally unique bucket name}"
FUNC=envsentinel-scan
ROLE=envsentinel-scan-role
RULE=envsentinel-env-uploaded
REGION="$(aws configure get region)"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

# 1. Bucket, with EventBridge notifications switched on (off by default)
aws s3 mb "s3://$BUCKET"
aws s3api put-bucket-notification-configuration --bucket "$BUCKET" \
  --notification-configuration '{"EventBridgeConfiguration": {}}'

# 2. Role the Lambda runs as: write logs + read objects in this bucket only
aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name "$ROLE" --policy-name read-bucket \
  --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [{\"Effect\": \"Allow\",
    \"Action\": \"s3:GetObject\",
    \"Resource\": \"arn:aws:s3:::$BUCKET/*\"}]}"
sleep 10  # new roles take a few seconds to become usable

# 3. The function
zip -j function.zip lambda_function.py
aws lambda create-function --function-name "$FUNC" \
  --runtime python3.13 --handler lambda_function.lambda_handler \
  --role "arn:aws:iam::$ACCOUNT:role/$ROLE" \
  --timeout 30 --zip-file fileb://function.zip

# 4. EventBridge rule (filename check) -> Lambda
sed "s/envsentinel-poc-CHANGEME/$BUCKET/" event_pattern.json > /tmp/pattern.json
aws events put-rule --name "$RULE" --event-pattern file:///tmp/pattern.json
aws lambda add-permission --function-name "$FUNC" \
  --statement-id eventbridge-invoke --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn "arn:aws:events:$REGION:$ACCOUNT:rule/$RULE"
aws events put-targets --rule "$RULE" \
  --targets "Id=scan,Arn=arn:aws:lambda:$REGION:$ACCOUNT:function:$FUNC"

echo "Deployed. Test with:"
echo "  aws s3 cp sample.env s3://$BUCKET/app/.env"
echo "  aws logs tail /aws/lambda/$FUNC --since 5m"
