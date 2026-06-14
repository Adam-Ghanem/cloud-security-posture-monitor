# Real AWS Scan Setup

This project is not only a mock dashboard. It includes a real AWS read-only scanner in `scanner/aws_scanner.py`.

## 1. Create a read-only scanner identity

Use an AWS IAM role or IAM user dedicated to this project. Give it only the permissions needed for posture checks:

- list S3 buckets
- read S3 public access block configuration
- list IAM users
- list IAM MFA devices
- describe EC2 security groups
- describe EBS volumes
- describe CloudTrail trails

Do not use an administrator account for scanning.

## 2. Configure credentials locally

Recommended method:

```bash
aws configure --profile cspm-demo
```

Then create a local `.env` file:

```bash
AWS_PROFILE=cspm-demo
AWS_REGION=us-east-1
OUTPUT_FILE=reports/aws-findings.json
```

Never commit `.env` or AWS keys.

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Run the scanner

```bash
python scanner/aws_scanner.py
```

The report will be saved to:

```text
reports/aws-findings.json
```

## 5. Current real checks

- S3 public access protection
- IAM users without MFA
- EC2 security groups exposing sensitive services broadly
- CloudTrail multi-region coverage
- EBS encryption status

## 6. Next production improvements

- Add Azure and GCP scanner modules
- Add CIS benchmark IDs
- Add severity scoring based on asset criticality
- Add PDF/CSV export
- Add scheduled scans using GitHub Actions or cron
- Add secure backend API to load the scan report into the dashboard
