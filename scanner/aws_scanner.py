"""AWS read-only Cloud Security Posture Monitor scanner.

This scanner uses boto3 with read-only permissions to review common cloud
configuration risks and export a JSON report for the dashboard.

Usage:
    pip install -r requirements.txt
    python scanner/aws_scanner.py

Do not commit cloud credentials. Use AWS CLI profiles, environment variables,
or an IAM role.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from dotenv import load_dotenv

load_dotenv()

Finding = Dict[str, Any]


def finding(service: str, severity: str, title: str, description: str, resource: str, remediation: str) -> Finding:
    return {
        "id": f"AWS-{service.upper()}-{abs(hash(resource + title)) % 100000}",
        "provider": "AWS",
        "service": service,
        "severity": severity,
        "title": title,
        "description": description,
        "resource": resource,
        "remediation": remediation,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


def session() -> boto3.Session:
    profile = os.getenv("AWS_PROFILE")
    region = os.getenv("AWS_REGION", "us-east-1")
    return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)


def check_s3_public_access(aws: boto3.Session) -> List[Finding]:
    s3 = aws.client("s3")
    results: List[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            if not all(config.get(item, False) for item in required):
                results.append(finding(
                    "S3", "High", "S3 public access controls are incomplete",
                    "The bucket does not have every public access protection enabled.",
                    name,
                    "Enable all S3 Block Public Access settings unless a documented business exception exists.",
                ))
        except ClientError:
            results.append(finding(
                "S3", "High", "S3 public access block is missing",
                "The bucket has no explicit public access block configuration.",
                name,
                "Apply bucket-level public access block settings.",
            ))
    return results


def check_iam_mfa(aws: boto3.Session) -> List[Finding]:
    iam = aws.client("iam")
    results: List[Finding] = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not devices:
                results.append(finding(
                    "IAM", "High", "IAM user without MFA",
                    "A human IAM user does not have multi-factor authentication enabled.",
                    username,
                    "Enable MFA or move access to federated identity and short-lived roles.",
                ))
    return results


def check_security_groups(aws: boto3.Session) -> List[Finding]:
    ec2 = aws.client("ec2")
    results: List[Finding] = []
    sensitive_ports = {22: "SSH", 3389: "RDP", 3306: "Database", 5432: "Database"}
    groups = ec2.describe_security_groups().get("SecurityGroups", [])
    for group in groups:
        group_id = group.get("GroupId", "unknown")
        for rule in group.get("IpPermissions", []):
            start = rule.get("FromPort")
            end = rule.get("ToPort")
            if start is None or end is None:
                continue
            is_open_to_all = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", []))
            if not is_open_to_all:
                continue
            for port, label in sensitive_ports.items():
                if start <= port <= end:
                    results.append(finding(
                        "EC2", "Critical" if port in [22, 3389] else "High",
                        f"{label} access is open broadly",
                        "A security group allows inbound access from any IPv4 address on a sensitive service.",
                        group_id,
                        "Restrict access to trusted networks or use VPN/bastion access.",
                    ))
    return results


def check_cloudtrail(aws: boto3.Session) -> List[Finding]:
    cloudtrail = aws.client("cloudtrail")
    results: List[Finding] = []
    trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
    if not trails:
        results.append(finding(
            "CloudTrail", "High", "CloudTrail is not configured",
            "No trail was detected for audit visibility.",
            "cloudtrail",
            "Create a multi-region trail and protect the log storage location.",
        ))
    for trail in trails:
        if not trail.get("IsMultiRegionTrail", False):
            results.append(finding(
                "CloudTrail", "Medium", "CloudTrail is not multi-region",
                "A trail exists but does not cover all regions.",
                trail.get("Name", "unknown"),
                "Enable multi-region logging for account-wide visibility.",
            ))
    return results


def check_ebs_encryption(aws: boto3.Session) -> List[Finding]:
    ec2 = aws.client("ec2")
    results: List[Finding] = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for volume in page.get("Volumes", []):
            if not volume.get("Encrypted", False):
                results.append(finding(
                    "EBS", "Medium", "EBS volume is not encrypted",
                    "A block storage volume is not encrypted at rest.",
                    volume.get("VolumeId", "unknown"),
                    "Enable encryption by default and migrate data to encrypted volumes.",
                ))
    return results


def run_scan() -> Dict[str, Any]:
    aws = session()
    checks = [check_s3_public_access, check_iam_mfa, check_security_groups, check_cloudtrail, check_ebs_encryption]
    all_findings: List[Finding] = []
    for check in checks:
        try:
            all_findings.extend(check(aws))
        except ClientError as error:
            all_findings.append(finding(
                "Scanner", "Medium", f"Scanner check failed: {check.__name__}",
                str(error), check.__name__,
                "Review the read-only IAM permissions granted to the scanner role.",
            ))
    return {
        "scanner": "cloud-security-posture-monitor",
        "provider": "AWS",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


def main() -> None:
    output = Path(os.getenv("OUTPUT_FILE", "reports/aws-findings.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = run_scan()
    except (NoCredentialsError, ProfileNotFound) as error:
        raise SystemExit("AWS credentials/profile not found. Configure AWS CLI or IAM role first. " + str(error))
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Saved report to {output}")


if __name__ == "__main__":
    main()
