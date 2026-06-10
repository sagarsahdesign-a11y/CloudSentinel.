import logging
from datetime import datetime, timezone
from typing import List, Optional, Callable
from botocore.exceptions import ClientError

from cloudsentinel.models import ScanResult, ScanMetadata, Finding
from cloudsentinel.utils import get_boto3_session, get_aws_client, calculate_scores
from cloudsentinel.checks import ALL_CHECK_FUNCTIONS

logger = logging.getLogger("cloudsentinel.scanner")

def scan(
    profile: Optional[str] = None,
    regions: Optional[List[str]] = None,
    status_callback: Optional[Callable[[str], None]] = None
) -> ScanResult:
    """
    Executes the AWS security scanner.
    
    1. Discovers current account identity via STS.
    2. Dynamically resolves active/enabled AWS regions.
    3. Iterates over all registered check runner functions.
    4. Gathers findings, calculates risk score, and summarizes severity counts.
    """
    if status_callback:
        status_callback("Initializing AWS Session...")
        
    session = get_boto3_session(profile=profile)
    
    # 1. Discover AWS Account ID
    account_id = "000000000000"
    try:
        if status_callback:
            status_callback("Discovering AWS Account Identity...")
        sts_client = get_aws_client(session, "sts")
        caller = sts_client.get_caller_identity()
        account_id = caller.get("AccountId", "000000000000")
    except ClientError as e:
        logger.warning(f"Could not discover AWS Account ID via STS: {str(e)}. Defaulting to placeholder.")
    except Exception as e:
        logger.warning(f"Unexpected error retrieving account identity: {str(e)}")

    # 2. Resolve target regions
    resolved_regions = []
    if regions:
        resolved_regions = regions
    else:
        if status_callback:
            status_callback("Querying active AWS regions...")
        try:
            ec2_client = get_aws_client(session, "ec2")
            res = ec2_client.describe_regions()
            resolved_regions = [r["RegionName"] for r in res.get("Regions", [])]
        except ClientError as e:
            fallback_region = session.region_name or "us-east-1"
            logger.warning(f"Could not query active AWS regions: {str(e)}. Defaulting to '{fallback_region}'.")
            resolved_regions = [fallback_region]
        except Exception as e:
            fallback_region = session.region_name or "us-east-1"
            logger.warning(f"Unexpected error listing regions: {str(e)}. Defaulting to '{fallback_region}'.")
            resolved_regions = [fallback_region]

    # 3. Execute check runners
    findings: List[Finding] = []
    
    check_modules = [
        ("IAM", "cloudsentinel.checks.iam"),
        ("S3", "cloudsentinel.checks.s3"),
        ("EC2", "cloudsentinel.checks.ec2"),
        ("Network (Security Groups)", "cloudsentinel.checks.security_groups"),
        ("CloudTrail", "cloudsentinel.checks.cloudtrail"),
        ("MFA", "cloudsentinel.checks.mfa")
    ]
    
    for i, run_fn in enumerate(ALL_CHECK_FUNCTIONS):
        cat_name, module_path = check_modules[i]
        if status_callback:
            status_callback(f"Scanning category: {cat_name}...")
            
        try:
            category_findings = run_fn(session, account_id, resolved_regions)
            findings.extend(category_findings)
        except Exception as e:
            logger.error(f"Error running checks in {module_path}: {str(e)}", exc_info=True)

    # 4. Score and compile findings
    category_scores, overall_score = calculate_scores(findings)
    
    severity_summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    for f in findings:
        severity_summary[f.severity.value] += 1
        
    metadata = ScanMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        aws_account_id=account_id,
        regions_scanned=resolved_regions,
        aws_profile=profile
    )
    
    return ScanResult(
        metadata=metadata,
        findings=findings,
        category_scores=category_scores,
        overall_score=overall_score,
        severity_summary=severity_summary
    )
