#!/bin/bash

# TCP Handshake Tutorial - AWS S3 Deployment Script
# Usage: ./deploy-to-s3.sh your-bucket-name [region]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if bucket name is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Bucket name is required${NC}"
    echo "Usage: $0 your-bucket-name [region]"
    echo "Example: $0 my-tcp-tutorial us-east-1"
    exit 1
fi

BUCKET_NAME=$1
REGION=${2:-us-east-1}

echo -e "${GREEN}TCP Handshake Tutorial - S3 Deployment${NC}"
echo "=========================================="
echo "Bucket: $BUCKET_NAME"
echo "Region: $REGION"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    echo "Install it from: https://aws.amazon.com/cli/"
    exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    echo "Run: aws configure"
    exit 1
fi

echo -e "${YELLOW}Step 1: Creating S3 bucket...${NC}"
if aws s3 ls "s3://$BUCKET_NAME" 2>&1 | grep -q 'NoSuchBucket'; then
    aws s3 mb "s3://$BUCKET_NAME" --region "$REGION"
    echo -e "${GREEN}✓ Bucket created${NC}"
else
    echo -e "${YELLOW}⚠ Bucket already exists, skipping creation${NC}"
fi

echo -e "${YELLOW}Step 2: Enabling static website hosting...${NC}"
aws s3 website "s3://$BUCKET_NAME" \
    --index-document index.html \
    --error-document index.html
echo -e "${GREEN}✓ Static website hosting enabled${NC}"

echo -e "${YELLOW}Step 3: Configuring bucket policy...${NC}"
# Create temporary policy file with actual bucket name
cat > /tmp/bucket-policy-temp.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
    }
  ]
}
EOF

# Disable block public access
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

aws s3api put-bucket-policy \
    --bucket "$BUCKET_NAME" \
    --policy file:///tmp/bucket-policy-temp.json

rm /tmp/bucket-policy-temp.json
echo -e "${GREEN}✓ Bucket policy configured${NC}"

echo -e "${YELLOW}Step 4: Uploading files...${NC}"
aws s3 sync . "s3://$BUCKET_NAME" \
    --exclude ".git/*" \
    --exclude "*.sh" \
    --exclude "bucket-policy.json" \
    --cache-control "max-age=3600" \
    --content-type "text/html"

echo -e "${GREEN}✓ Files uploaded${NC}"

echo ""
echo -e "${GREEN}=========================================="
echo "Deployment Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${GREEN}Your tutorial is now available at:${NC}"
echo "http://$BUCKET_NAME.s3-website-$REGION.amazonaws.com"
echo ""
echo -e "${YELLOW}Optional: Set up CloudFront for HTTPS${NC}"
echo "https://console.aws.amazon.com/cloudfront/home"
echo ""
echo -e "${YELLOW}To update the tutorial:${NC}"
echo "aws s3 sync . s3://$BUCKET_NAME --exclude '.git/*' --exclude '*.sh' --cache-control 'max-age=3600'"
echo ""
