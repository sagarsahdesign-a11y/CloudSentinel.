import logging
from typing import List
from botocore.exceptions import ClientError

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client

logger = logging.getLogger("cloudsentinel.checks.cloudtrail")

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all CloudTrail security checks."""
    findings = []
    
    # CloudTrail check only needs to run once globally/regionally.
    # We run it in the primary/first region of the scan scope.
    if not regions:
        return findings
    primary_region = regions[0]
    client = get_aws_client(session, "cloudtrail", region_name=primary_region)
    
    try:
        # Describe all trails (including those created in other regions if shadow trails are active)
        response = client.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])
    except ClientError as e:
        logger.error(f"Failed to describe CloudTrails: {str(e)}")
        return findings

    if not trails:
        # CT-001: CloudTrail Disabled (no trails exist)
        meta = CHECK_REGISTRY["CT-001"]
        findings.append(Finding(
            check_id="CT-001",
            service=meta["service"],
            resource=f"arn:aws:cloudtrail:{primary_region}:{account_id}:trail/*",
            severity=Severity[meta["severity"]],
            title=meta["title"],
            description="No CloudTrail trails exist in the account.",
            recommendation=meta["recommendation"],
            reference=meta["reference"],
            cis_control=meta["cis_control"],
            region="global"
        ))
        return findings

    has_active_trail = False
    has_multi_region_trail = False

    for trail in trails:
        trail_arn = trail["TrailARN"]
        trail_name = trail["Name"]
        trail_region = trail.get("HomeRegion", primary_region)

        # Get the status of the trail
        try:
            status = client.get_trail_status(Name=trail_arn)
            if status.get("IsLogging", False):
                has_active_trail = True
                if trail.get("IsMultiRegionTrail", False):
                    has_multi_region_trail = True
        except ClientError as e:
            logger.error(f"Failed to get status for trail {trail_name}: {str(e)}")
            # Fallback to checking basic trail details
            if trail.get("IsMultiRegionTrail", False):
                has_multi_region_trail = True

        # --- CT-002: Missing Log Validation ---
        if not trail.get("LogFileValidationEnabled", False):
            meta = CHECK_REGISTRY["CT-002"]
            findings.append(Finding(
                check_id="CT-002",
                service=meta["service"],
                resource=trail_arn,
                severity=Severity[meta["severity"]],
                title=meta["title"],
                description=f"CloudTrail '{trail_name}' does not have log file validation enabled.",
                recommendation=meta["recommendation"],
                reference=meta["reference"],
                cis_control=meta["cis_control"],
                region=trail_region
            ))

        # --- CT-003: No Multi-Region Trail (check individual trail) ---
        if not trail.get("IsMultiRegionTrail", False):
            meta = CHECK_REGISTRY["CT-003"]
            findings.append(Finding(
                check_id="CT-003",
                service=meta["service"],
                resource=trail_arn,
                severity=Severity[meta["severity"]],
                title=meta["title"],
                description=f"CloudTrail '{trail_name}' is a single-region trail and does not capture events in other regions.",
                recommendation=meta["recommendation"],
                reference=meta["reference"],
                cis_control=meta["cis_control"],
                region=trail_region
            ))

    # If CloudTrail exists but none are actually logging (inactive)
    if not has_active_trail:
        meta = CHECK_REGISTRY["CT-001"]
        findings.append(Finding(
            check_id="CT-001",
            service=meta["service"],
            resource=f"arn:aws:cloudtrail:{primary_region}:{account_id}:trail/*",
            severity=Severity[meta["severity"]],
            title=meta["title"],
            description="CloudTrail trails are configured, but none are actively logging events.",
            recommendation=meta["recommendation"],
            reference=meta["reference"],
            cis_control=meta["cis_control"],
            region="global"
        ))

    return findings
