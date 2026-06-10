from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    check_id: str
    service: str
    resource: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    reference: str
    cis_control: str
    region: str = "global"

class CategoryBreakdown(BaseModel):
    score: int
    findings_count: int
    severity_counts: Dict[str, int]

class ScanMetadata(BaseModel):
    timestamp: str
    aws_account_id: str
    regions_scanned: List[str]
    aws_profile: Optional[str] = None
    scanner_version: str = "1.0.0"

class ScanResult(BaseModel):
    metadata: ScanMetadata
    findings: List[Finding]
    category_scores: Dict[str, int]
    overall_score: int
    severity_summary: Dict[str, int]

# Central Check Registry containing metadata for all 24 checks
CHECK_REGISTRY = {
    # 1. IAM
    "IAM-001": {
        "service": "IAM",
        "title": "Inactive Users",
        "description": "IAM users with active passwords or access keys that have not been used for more than 90 days.",
        "recommendation": "Identify these inactive users and disable their console passwords or deactivate/delete their unused access keys.",
        "reference": "AWS Security Best Practices - Deactivate Unused Credentials",
        "cis_control": "1.12",
        "severity": "MEDIUM"
    },
    "IAM-002": {
        "service": "IAM",
        "title": "Access Keys Older than 90 Days",
        "description": "Active IAM access keys that have not been rotated in the last 90 days.",
        "recommendation": "Rotate active access keys regularly (every 90 days or less) to reduce exposure risk in case of credential leaks.",
        "reference": "AWS Security Best Practices - Rotate Access Keys",
        "cis_control": "1.14",
        "severity": "MEDIUM"
    },
    "IAM-003": {
        "service": "IAM",
        "title": "AdministratorAccess Assignment",
        "description": "IAM policies containing the AdministratorAccess managed policy are attached directly to users, groups, or roles.",
        "recommendation": "Apply the principle of least privilege. Remove AdministratorAccess and attach specific permissions instead.",
        "reference": "AWS IAM Best Practices - Grant Least Privilege",
        "cis_control": "1.16",
        "severity": "HIGH"
    },
    "IAM-004": {
        "service": "IAM",
        "title": "Wildcard Permissions",
        "description": "Attached IAM or inline policies contain permissive '*' statements in Action or Resource fields.",
        "recommendation": "Restrict the policy definition to explicitly list required service actions and target resource ARNs.",
        "reference": "AWS IAM Best Practices - Avoid Wildcard Permissions",
        "cis_control": "1.22",
        "severity": "HIGH"
    },
    # 2. S3
    "S3-001": {
        "service": "S3",
        "title": "Public Buckets",
        "description": "S3 bucket does not block public access, exposing content to potential external users.",
        "recommendation": "Enable S3 Block Public Access at the bucket level or account level unless public access is explicitly required.",
        "reference": "AWS S3 Security Best Practices - Block Public Access",
        "cis_control": "2.1.1",
        "severity": "CRITICAL"
    },
    "S3-002": {
        "service": "S3",
        "title": "Public ACLs",
        "description": "S3 bucket Access Control List (ACL) allows public read or write permissions to all authenticated users or anyone.",
        "recommendation": "Modify the bucket ACL to remove grants for 'AllUsers' or 'AuthenticatedUsers'. Prefer using bucket policies instead of ACLs.",
        "reference": "AWS S3 Security Best Practices - Disable ACLs",
        "cis_control": "2.1.2",
        "severity": "CRITICAL"
    },
    "S3-003": {
        "service": "S3",
        "title": "Missing Default Encryption",
        "description": "S3 bucket does not have Server-Side Encryption (SSE) enabled by default.",
        "recommendation": "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket so all uploaded files are encrypted automatically.",
        "reference": "AWS S3 Security Best Practices - Enable Default Encryption",
        "cis_control": "2.1.3",
        "severity": "HIGH"
    },
    "S3-004": {
        "service": "S3",
        "title": "Missing Versioning",
        "description": "S3 bucket has versioning disabled, meaning deleted or overwritten files cannot be recovered.",
        "recommendation": "Enable versioning on the S3 bucket to maintain a history of object versions and protect against accidental overwrites/deletions.",
        "reference": "AWS S3 Security Best Practices - Enable Versioning",
        "cis_control": "2.1.4",
        "severity": "MEDIUM"
    },
    "S3-005": {
        "service": "S3",
        "title": "Missing Logging",
        "description": "S3 server access logging is disabled. Changes and access requests cannot be fully audited.",
        "recommendation": "Configure server access logging on the bucket and specify a target bucket for storing audit logs.",
        "reference": "AWS S3 Security Best Practices - Enable Access Logging",
        "cis_control": "2.1.5",
        "severity": "MEDIUM"
    },
    # 3. EC2
    "EC2-001": {
        "service": "EC2",
        "title": "Public IP Exposure",
        "description": "EC2 instance has a public IP address, making it directly routable from the internet.",
        "recommendation": "Place the instance in a private subnet and access it via a NAT Gateway, Bastion host, or AWS Systems Manager Session Manager.",
        "reference": "AWS EC2 Security - Private Subnets",
        "cis_control": "4.1",
        "severity": "HIGH"
    },
    "EC2-002": {
        "service": "EC2",
        "title": "IMDSv2 Disabled",
        "description": "Instance Metadata Service Version 1 (IMDSv1) is enabled. IMDSv2 is not required, exposing the instance to potential SSRF risks.",
        "recommendation": "Modify instance metadata options to set HttpTokens to 'required' to enforce IMDSv2 usage.",
        "reference": "AWS EC2 Security - Transition to IMDSv2",
        "cis_control": "4.2",
        "severity": "HIGH"
    },
    "EC2-003": {
        "service": "EC2",
        "title": "Unencrypted EBS Volumes",
        "description": "EBS volumes attached to the instance are unencrypted, or account-level default EBS encryption is disabled.",
        "recommendation": "Enable EBS encryption by default in the region, and encrypt existing unencrypted volumes by copying them as encrypted snapshots.",
        "reference": "AWS EBS Security - Encrypting Volumes",
        "cis_control": "4.3",
        "severity": "HIGH"
    },
    "EC2-004": {
        "service": "EC2",
        "title": "Legacy Instance Types",
        "description": "Instance is running on a legacy/previous-generation instance type (e.g. t1, t2, m1, c1, m3).",
        "recommendation": "Upgrade to current-generation instance types (e.g. t3, m5, c5) for improved performance, security, and lower costs.",
        "reference": "AWS EC2 - Previous Generation Instances",
        "cis_control": "4.4",
        "severity": "LOW"
    },
    # 4. Security Groups
    "SG-001": {
        "service": "Network",
        "title": "SSH Open to Internet",
        "description": "Security Group allows inbound traffic on port 22 (SSH) from any IP address (0.0.0.0/0 or ::/0).",
        "recommendation": "Restrict inbound port 22 to specific corporate IP ranges or use AWS Systems Manager Session Manager.",
        "reference": "AWS VPC Security - Restrict SSH Access",
        "cis_control": "5.1",
        "severity": "CRITICAL"
    },
    "SG-002": {
        "service": "Network",
        "title": "RDP Open to Internet",
        "description": "Security Group allows inbound traffic on port 3389 (RDP) from any IP address (0.0.0.0/0 or ::/0).",
        "recommendation": "Restrict inbound port 3389 to specific trusted IP ranges or use a VPN/SSM connection.",
        "reference": "AWS VPC Security - Restrict RDP Access",
        "cis_control": "5.2",
        "severity": "CRITICAL"
    },
    "SG-003": {
        "service": "Network",
        "title": "Database Ports Exposed",
        "description": "Security Group allows inbound database traffic (MySQL/3306, PostgreSQL/5432, MSSQL/1433, Oracle/1521, etc.) from any IP (0.0.0.0/0 or ::/0).",
        "recommendation": "Restrict database access to the web server's security group or internal VPC CIDR ranges only.",
        "reference": "AWS VPC Security - Protect Databases",
        "cis_control": "5.3",
        "severity": "CRITICAL"
    },
    "SG-004": {
        "service": "Network",
        "title": "Excessive Rules",
        "description": "Security Group contains more than 30 inbound or outbound rules, increasing configuration complexity and potential audit gaps.",
        "recommendation": "Consolidate security group rules or decompose them into separate security groups assigned to specific tiers.",
        "reference": "AWS VPC Security - Security Group Limits",
        "cis_control": "5.4",
        "severity": "LOW"
    },
    "SG-005": {
        "service": "Network",
        "title": "Unrestricted Outbound Access",
        "description": "Security Group allows unrestricted outbound traffic (egress to 0.0.0.0/0 on all protocols).",
        "recommendation": "Restrict outbound rules to allow only necessary protocols and ports to specific destination networks.",
        "reference": "AWS VPC Security - Restrict Egress Traffic",
        "cis_control": "5.5",
        "severity": "LOW"
    },
    # 5. CloudTrail
    "CT-001": {
        "service": "CloudTrail",
        "title": "CloudTrail Disabled",
        "description": "AWS CloudTrail is disabled. API activities and user actions cannot be audited across the account.",
        "recommendation": "Enable AWS CloudTrail in all regions to log audit events into an S3 bucket.",
        "reference": "AWS CloudTrail Best Practices - Enable CloudTrail",
        "cis_control": "3.1",
        "severity": "CRITICAL"
    },
    "CT-002": {
        "service": "CloudTrail",
        "title": "Missing Log Validation",
        "description": "CloudTrail log file integrity validation is disabled. Logs could be altered or deleted without detection.",
        "recommendation": "Enable log file validation on all active trails to ensure cryptographic integrity of log files.",
        "reference": "AWS CloudTrail - Enable Log File Validation",
        "cis_control": "3.2",
        "severity": "HIGH"
    },
    "CT-003": {
        "service": "CloudTrail",
        "title": "No Multi-Region Trail",
        "description": "There is no multi-region CloudTrail configured. API events in inactive regions will not be centralized.",
        "recommendation": "Configure a multi-region trail so that events from all AWS regions are logged in a single centralized S3 bucket.",
        "reference": "AWS CloudTrail - Multi-Region Trails",
        "cis_control": "3.3",
        "severity": "MEDIUM"
    },
    # 6. MFA
    "MFA-001": {
        "service": "MFA",
        "title": "Root MFA Disabled",
        "description": "The AWS Root account does not have Multi-Factor Authentication (MFA) enabled, leaving it highly vulnerable.",
        "recommendation": "Immediately enable a virtual or hardware MFA device on the AWS account Root user.",
        "reference": "AWS Security - Enable Root MFA",
        "cis_control": "1.1",
        "severity": "CRITICAL"
    },
    "MFA-002": {
        "service": "MFA",
        "title": "IAM Users without MFA",
        "description": "One or more active IAM users do not have a Multi-Factor Authentication (MFA) device configured.",
        "recommendation": "Enforce MFA for all IAM users with console access via IAM policy or AWS Organizations SCPs.",
        "reference": "AWS IAM - Enforce MFA",
        "cis_control": "1.2",
        "severity": "HIGH"
    }
}
