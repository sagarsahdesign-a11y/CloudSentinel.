import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client

logger = logging.getLogger("cloudsentinel.checks.s3")

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all S3-related security checks."""
    findings = []
    
    # We start with the global S3 client to list buckets
    s3_global = get_aws_client(session, "s3")
    
    try:
        response = s3_global.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as e:
        logger.error(f"Failed to list S3 buckets: {str(e)}")
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        
        # 1. Detect bucket region to avoid 301 redirection issues
        try:
            loc = s3_global.get_bucket_location(Bucket=bucket_name)
            bucket_region = loc.get("LocationConstraint")
            if not bucket_region:
                bucket_region = "us-east-1"
            elif bucket_region == "EU":
                bucket_region = "eu-west-1"
        except ClientError as e:
            logger.warning(f"Could not get location for bucket {bucket_name}: {str(e)}. Defaulting to us-east-1.")
            bucket_region = "us-east-1"

        # If we are filtering by specific regions and this bucket is not in the scope, skip
        if regions and bucket_region not in regions:
            logger.debug(f"Skipping bucket {bucket_name} in region {bucket_region} as it is not in the scan scope.")
            continue
            
        # Create regional S3 client for checking bucket configuration
        s3_regional = get_aws_client(session, "s3", region_name=bucket_region)

        # --- S3-001: Public Buckets (Block Public Access & Bucket Policy check) ---
        is_public = False
        bpa_found = True
        try:
            bpa = s3_regional.get_public_access_block(Bucket=bucket_name)
            bpa_config = bpa.get("PublicAccessBlockConfiguration", {})
            # If any of these are False, BPA is not fully enabled
            if not all([
                bpa_config.get("BlockPublicAcls", False),
                bpa_config.get("IgnorePublicAcls", False),
                bpa_config.get("BlockPublicPolicy", False),
                bpa_config.get("RestrictPublicBuckets", False)
            ]):
                is_public = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                is_public = True
                bpa_found = False
            else:
                logger.error(f"Error checking BPA for bucket {bucket_name}: {str(e)}")

        # Check S3 Bucket Policy for public access if BPA is disabled/missing
        if is_public:
            try:
                policy_status = s3_regional.get_bucket_policy_status(Bucket=bucket_name)
                if policy_status.get("PolicyStatus", {}).get("IsPublic", False):
                    is_public = True
                else:
                    # BPA might be false but policy is not public
                    pass
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    logger.debug(f"Error checking policy status for bucket {bucket_name}: {str(e)}")

        if is_public:
            meta = CHECK_REGISTRY["S3-001"]
            findings.append(Finding(
                check_id="S3-001",
                service=meta["service"],
                resource=bucket_arn,
                severity=Severity[meta["severity"]],
                title=meta["title"],
                description=f"S3 bucket '{bucket_name}' has Block Public Access disabled or is exposed via a public bucket policy.",
                recommendation=meta["recommendation"],
                reference=meta["reference"],
                cis_control=meta["cis_control"],
                region=bucket_region
            ))

        # --- S3-002: Public ACLs ---
        try:
            acl = s3_regional.get_bucket_acl(Bucket=bucket_name)
            has_public_acl = False
            public_grant_reasons = []
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group":
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        has_public_acl = True
                        public_grant_reasons.append(f"Grantee '{uri.split('/')[-1]}' is allowed '{grant.get('Permission')}'")
            
            if has_public_acl:
                meta = CHECK_REGISTRY["S3-002"]
                findings.append(Finding(
                    check_id="S3-002",
                    service=meta["service"],
                    resource=bucket_arn,
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"S3 bucket '{bucket_name}' allows public access via ACL: {', '.join(public_grant_reasons)}.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region=bucket_region
                ))
        except ClientError as e:
            logger.error(f"Error checking ACL for bucket {bucket_name}: {str(e)}")

        # --- S3-003: Missing Default Encryption ---
        try:
            s3_regional.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                meta = CHECK_REGISTRY["S3-003"]
                findings.append(Finding(
                    check_id="S3-003",
                    service=meta["service"],
                    resource=bucket_arn,
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"S3 bucket '{bucket_name}' does not have Default Server-Side Encryption enabled.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region=bucket_region
                ))
            else:
                logger.error(f"Error checking encryption for bucket {bucket_name}: {str(e)}")

        # --- S3-004: Missing Versioning ---
        try:
            ver = s3_regional.get_bucket_versioning(Bucket=bucket_name)
            if ver.get("Status") != "Enabled":
                meta = CHECK_REGISTRY["S3-004"]
                findings.append(Finding(
                    check_id="S3-004",
                    service=meta["service"],
                    resource=bucket_arn,
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"S3 bucket '{bucket_name}' has versioning disabled or suspended.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region=bucket_region
                ))
        except ClientError as e:
            logger.error(f"Error checking versioning for bucket {bucket_name}: {str(e)}")

        # --- S3-005: Missing Logging ---
        try:
            log = s3_regional.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in log:
                meta = CHECK_REGISTRY["S3-005"]
                findings.append(Finding(
                    check_id="S3-005",
                    service=meta["service"],
                    resource=bucket_arn,
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"S3 bucket '{bucket_name}' server access logging is disabled.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region=bucket_region
                ))
        except ClientError as e:
            logger.error(f"Error checking logging for bucket {bucket_name}: {str(e)}")

    return findings
