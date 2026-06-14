# Architecture

## Goal

Cloud Security Posture Monitor is a defensive CSPM MVP. It collects cloud configuration findings using read-only APIs and visualizes risk in a simple dashboard.

## Components

```text
Cloud Account
   |
   | read-only API calls
   v
Python Scanner
   |
   | JSON report
   v
Dashboard / Reports
```

## Frontend

The React dashboard displays:

- posture score
- severity counters
- finding cards
- remediation guidance

## Scanner

The first real scanner is AWS-based and located at:

```text
scanner/aws_scanner.py
```

It uses `boto3` and checks common misconfigurations without modifying cloud resources.

## Data flow

1. The user configures AWS credentials locally or uses an IAM role.
2. The scanner calls read-only AWS APIs.
3. The scanner writes `reports/aws-findings.json`.
4. The dashboard can be extended to load the generated report.

## Security principles

- Read-only access only.
- No cloud secrets committed to GitHub.
- Least privilege for scanner identity.
- Findings are used for remediation, not exploitation.
