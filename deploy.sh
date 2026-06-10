#!/bin/bash
# deploy.sh — Reference deployment script for CDK stacks (InfraGraphNeo4j + InfraGraphCompute)
# Edit AWS_PROFILE and AWS_DEFAULT_REGION before running.
# See infra/README.md for full deployment instructions.
set -euo pipefail

# --- Configuration ---
AWS_PROFILE="YOUR_AWS_PROFILE"
AWS_DEFAULT_REGION="us-east-1"
export AWS_PROFILE AWS_DEFAULT_REGION

# --- SSO session check ---
echo "=== AWS Account Validation ==="
echo "Checking credentials for profile: $AWS_PROFILE ..."

if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "ERROR: No valid AWS credentials."
    echo "Run: aws sso login --profile $AWS_PROFILE"
    exit 1
fi

CALLER_INFO=$(aws sts get-caller-identity)
ACCOUNT_ID=$(echo "$CALLER_INFO" | jq -r .Account)
USER_ARN=$(echo "$CALLER_INFO" | jq -r .Arn)

echo ""
echo "  AWS Profile : $AWS_PROFILE"
echo "  Account     : $ACCOUNT_ID"
echo "  Identity    : $USER_ARN"
echo "  Region      : $AWS_DEFAULT_REGION"
echo ""

# --- Human-in-the-loop confirmation ---
read -p "Deploy to this account? (yes/no) " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

# --- Podman setup ---
echo ""
echo "=== Podman Setup ==="

if ! podman machine list 2>/dev/null | grep -q "Currently running"; then
    echo "Starting Podman machine..."
    podman machine start
fi

export DOCKER_HOST="unix://${TMPDIR}podman/podman-machine-default-api.sock"

# --- ECR login ---
echo ""
echo "=== ECR Login ==="

# Create ECR repo if it doesn't exist
ECR_REPO="aws-infra-graph/mcp-server"
aws ecr describe-repositories --repository-names "$ECR_REPO" >/dev/null 2>&1 || \
    aws ecr create-repository --repository-name "$ECR_REPO" --image-scanning-configuration scanOnPush=true

ECR_URI="$ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com"
aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | \
    podman login --username AWS --password-stdin "$ECR_URI"

echo "Logged into ECR: $ECR_URI"

# --- Build & push ---
echo ""
echo "=== Build & Push ==="

IMAGE_TAG="$ECR_URI/$ECR_REPO:latest"
podman build -t "$IMAGE_TAG" --tls-verify=false .
podman push "$IMAGE_TAG" --tls-verify=false

echo "Pushed: $IMAGE_TAG"

# --- CDK deploy ---
echo ""
echo "=== CDK Deploy ==="

cd infra
pip install -q -r requirements.txt 2>/dev/null

# --force ensures CDK creates a changeset even when the template has no structural
# diff (code-only changes). Without it, CDK exits silently and ECS keeps the old image.
cdk deploy --all \
    --require-approval broadening \
    --force \
    -c aws_profile="$AWS_PROFILE" \
    -c account="$ACCOUNT_ID" \
    -c region="$AWS_DEFAULT_REGION"

echo ""
echo "=== Done ==="
