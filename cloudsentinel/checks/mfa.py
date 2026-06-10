import csv
import io
import logging
from typing import List
from botocore.exceptions import ClientError

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client
from cloudsentinel.checks.iam import get_credential_report

logger = logging.getLogger("cloudsentinel.checks.mfa")

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all MFA-related security checks."""
    findings = []
    client = get_aws_client(session, "iam")
    
    # --- MFA-001: Root MFA Disabled ---
    try:
        summary = client.get_account_summary()
        summary_map = summary.get("SummaryMap", {})
        root_mfa_enabled = summary_map.get("AccountMFAEnabled", 0)
        
        if root_mfa_enabled == 0:
            meta = CHECK_REGISTRY["MFA-001"]
            findings.append(Finding(
                check_id="MFA-001",
                service=meta["service"],
                resource=f"arn:aws:iam::{account_id}:root",
                severity=Severity[meta["severity"]],
                title=meta["title"],
                description="The AWS Root account does not have Multi-Factor Authentication (MFA) enabled.",
                recommendation=meta["recommendation"],
                reference=meta["reference"],
                cis_control=meta["cis_control"],
                region="global"
            ))
    except ClientError as e:
        logger.error(f"Failed to get IAM account summary for Root MFA status check: {str(e)}")

    # --- MFA-002: IAM Users without MFA ---
    report_csv = get_credential_report(client)
    if report_csv:
        reader = csv.DictReader(io.StringIO(report_csv))
        for row in reader:
            username = row.get("user")
            user_arn = row.get("arn")
            if not username or username == "<root_account>":
                continue
                
            mfa_active = row.get("mfa_active") == "true"
            if not mfa_active:
                meta = CHECK_REGISTRY["MFA-002"]
                findings.append(Finding(
                    check_id="MFA-002",
                    service=meta["service"],
                    resource=user_arn,
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"IAM user '{username}' does not have a registered Multi-Factor Authentication (MFA) device.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region="global"
                ))

    return findings
