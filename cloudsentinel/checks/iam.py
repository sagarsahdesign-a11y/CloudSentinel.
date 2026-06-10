import csv
import io
import time
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from botocore.exceptions import ClientError
import urllib.parse

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client

logger = logging.getLogger("cloudsentinel.checks.iam")

def parse_date(date_str: str) -> Optional[datetime]:
    if not date_str or date_str in ("N/A", "no_information", "not_supported", "false", "true"):
        return None
    try:
        cleaned = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None

def get_credential_report(client) -> Optional[str]:
    """Requests and retrieves the credential report, polling if necessary."""
    for _ in range(10):
        try:
            res = client.generate_credential_report()
            if res.get("State") == "COMPLETE":
                break
        except ClientError as e:
            logger.debug(f"Credential report generation state check failed: {str(e)}")
        time.sleep(1)
    try:
        report = client.get_credential_report()
        return report["Content"].decode("utf-8")
    except Exception as e:
        logger.warning(f"Could not retrieve IAM credential report: {str(e)}")
        return None

def check_wildcard_statement(statement: Dict[str, Any]) -> bool:
    """Returns True if the statement allows wildcard actions or resources under Effect: Allow."""
    if statement.get("Effect") != "Allow":
        return False
    
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
        
    if "*" in actions or "*" in resources:
        return True
    return False

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all IAM-related security checks."""
    findings = []
    client = get_aws_client(session, "iam")
    
    # 1 & 2: Inactive Users & Access Key Age (using Credential Report)
    report_csv = get_credential_report(client)
    if report_csv:
        reader = csv.DictReader(io.StringIO(report_csv))
        now = datetime.now(timezone.utc)
        
        for row in reader:
            username = row.get("user")
            user_arn = row.get("arn")
            if not username or username == "<root_account>":
                continue
                
            user_creation_time = parse_date(row.get("user_creation_time"))
            password_active = row.get("password_active") == "true"
            password_last_used = parse_date(row.get("password_last_used"))
            
            key1_active = row.get("access_key_1_active") == "true"
            key1_last_used = parse_date(row.get("access_key_1_last_used_date"))
            key1_rotated = parse_date(row.get("access_key_1_last_rotated"))
            
            key2_active = row.get("access_key_2_active") == "true"
            key2_last_used = parse_date(row.get("access_key_2_last_used_date"))
            key2_rotated = parse_date(row.get("access_key_2_last_rotated"))
            
            # --- IAM-001: Inactive Users ---
            # Active credentials (password or access keys) check
            has_active_credentials = password_active or key1_active or key2_active
            
            if has_active_credentials:
                # Check times
                dates_to_check = []
                if password_active:
                    if password_last_used:
                        dates_to_check.append(password_last_used)
                    elif user_creation_time:
                        dates_to_check.append(user_creation_time)
                        
                if key1_active:
                    if key1_last_used:
                        dates_to_check.append(key1_last_used)
                    elif key1_rotated:
                        dates_to_check.append(key1_rotated)
                        
                if key2_active:
                    if key2_last_used:
                        dates_to_check.append(key2_last_used)
                    elif key2_rotated:
                        dates_to_check.append(key2_rotated)
                
                # If all usage dates are older than 90 days, or we have active credentials with no dates (highly unlikely)
                if dates_to_check and all((now - d).days > 90 for d in dates_to_check):
                    meta = CHECK_REGISTRY["IAM-001"]
                    findings.append(Finding(
                        check_id="IAM-001",
                        service=meta["service"],
                        resource=user_arn,
                        severity=Severity[meta["severity"]],
                        title=meta["title"],
                        description=f"User '{username}' has active credentials but has been inactive for > 90 days.",
                        recommendation=meta["recommendation"],
                        reference=meta["reference"],
                        cis_control=meta["cis_control"]
                    ))

            # --- IAM-002: Access Keys Older than 90 Days ---
            for key_idx, key_active, key_rotated in [("1", key1_active, key1_rotated), ("2", key2_active, key2_rotated)]:
                if key_active and key_rotated:
                    days_old = (now - key_rotated).days
                    if days_old > 90:
                        meta = CHECK_REGISTRY["IAM-002"]
                        findings.append(Finding(
                            check_id="IAM-002",
                            service=meta["service"],
                            resource=f"{user_arn}/accesskey/{key_idx}",
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"User '{username}' access key {key_idx} is {days_old} days old (exceeds 90 days).",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"]
                        ))

    # 3 & 4: AdministratorAccess assignment & Wildcard permissions
    # Let's inspect Users, Groups, and Roles
    try:
        users = client.list_users().get("Users", [])
        for u in users:
            uname = u["UserName"]
            uarn = u["Arn"]
            
            # IAM-003: Attached Policies
            try:
                attached_policies = client.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                for policy in attached_policies:
                    if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                        meta = CHECK_REGISTRY["IAM-003"]
                        findings.append(Finding(
                            check_id="IAM-003",
                            service=meta["service"],
                            resource=uarn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"User '{uname}' has AdministratorAccess policy directly attached.",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"]
                        ))
                    
                    # IAM-004: Inspect customer managed policies
                    if not policy["PolicyArn"].startswith("arn:aws:iam::aws:policy/"):
                        p_detail = client.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                        p_ver = client.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=p_detail["DefaultVersionId"])["PolicyVersion"]
                        doc = p_ver["Document"]
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for stmt in statements:
                            if check_wildcard_statement(stmt):
                                meta = CHECK_REGISTRY["IAM-004"]
                                findings.append(Finding(
                                    check_id="IAM-004",
                                    service=meta["service"],
                                    resource=policy["PolicyArn"],
                                    severity=Severity[meta["severity"]],
                                    title=meta["title"],
                                    description=f"Customer managed policy '{policy['PolicyName']}' attached to User '{uname}' allows wildcard '*' actions or resources.",
                                    recommendation=meta["recommendation"],
                                    reference=meta["reference"],
                                    cis_control=meta["cis_control"]
                                ))
                                break
            except ClientError as e:
                logger.error(f"Error checking user policies for {uname}: {str(e)}")

            # IAM-004: Inline Policies
            try:
                inline_policies = client.list_user_policies(UserName=uname).get("PolicyNames", [])
                for pname in inline_policies:
                    p_doc = client.get_user_policy(UserName=uname, PolicyName=pname)["PolicyDocument"]
                    statements = p_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if check_wildcard_statement(stmt):
                            meta = CHECK_REGISTRY["IAM-004"]
                            findings.append(Finding(
                                check_id="IAM-004",
                                service=meta["service"],
                                resource=f"{uarn}/policy/{pname}",
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"User '{uname}' inline policy '{pname}' allows wildcard '*' actions or resources.",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"]
                            ))
                            break
            except ClientError as e:
                logger.error(f"Error checking user inline policies for {uname}: {str(e)}")

    except ClientError as e:
        logger.error(f"Failed to list IAM users: {str(e)}")

    # Groups
    try:
        groups = client.list_groups().get("Groups", [])
        for g in groups:
            gname = g["GroupName"]
            garn = g["Arn"]
            
            # IAM-003: Attached Policies
            try:
                attached_policies = client.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
                for policy in attached_policies:
                    if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                        meta = CHECK_REGISTRY["IAM-003"]
                        findings.append(Finding(
                            check_id="IAM-003",
                            service=meta["service"],
                            resource=garn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"Group '{gname}' has AdministratorAccess policy directly attached.",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"]
                        ))
                    
                    if not policy["PolicyArn"].startswith("arn:aws:iam::aws:policy/"):
                        p_detail = client.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                        p_ver = client.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=p_detail["DefaultVersionId"])["PolicyVersion"]
                        doc = p_ver["Document"]
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for stmt in statements:
                            if check_wildcard_statement(stmt):
                                meta = CHECK_REGISTRY["IAM-004"]
                                findings.append(Finding(
                                    check_id="IAM-004",
                                    service=meta["service"],
                                    resource=policy["PolicyArn"],
                                    severity=Severity[meta["severity"]],
                                    title=meta["title"],
                                    description=f"Customer managed policy '{policy['PolicyName']}' attached to Group '{gname}' allows wildcard '*' actions or resources.",
                                    recommendation=meta["recommendation"],
                                    reference=meta["reference"],
                                    cis_control=meta["cis_control"]
                                ))
                                break
            except ClientError as e:
                logger.error(f"Error checking group policies for {gname}: {str(e)}")

            # IAM-004: Inline Policies
            try:
                inline_policies = client.list_group_policies(GroupName=gname).get("PolicyNames", [])
                for pname in inline_policies:
                    p_doc = client.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"]
                    statements = p_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if check_wildcard_statement(stmt):
                            meta = CHECK_REGISTRY["IAM-004"]
                            findings.append(Finding(
                                check_id="IAM-004",
                                service=meta["service"],
                                resource=f"{garn}/policy/{pname}",
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"Group '{gname}' inline policy '{pname}' allows wildcard '*' actions or resources.",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"]
                            ))
                            break
            except ClientError as e:
                logger.error(f"Error checking group inline policies for {gname}: {str(e)}")

    except ClientError as e:
        logger.error(f"Failed to list IAM groups: {str(e)}")

    # Roles
    try:
        roles = client.list_roles().get("Roles", [])
        for r in roles:
            rname = r["RoleName"]
            rarn = r["Arn"]
            
            # Exclude AWS service-linked roles
            if "/aws-service-role/" in rarn:
                continue
                
            # IAM-003: Attached Policies
            try:
                attached_policies = client.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                for policy in attached_policies:
                    if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                        meta = CHECK_REGISTRY["IAM-003"]
                        findings.append(Finding(
                            check_id="IAM-003",
                            service=meta["service"],
                            resource=rarn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"Role '{rname}' has AdministratorAccess policy directly attached.",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"]
                        ))
                    
                    if not policy["PolicyArn"].startswith("arn:aws:iam::aws:policy/"):
                        p_detail = client.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                        p_ver = client.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=p_detail["DefaultVersionId"])["PolicyVersion"]
                        doc = p_ver["Document"]
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for stmt in statements:
                            if check_wildcard_statement(stmt):
                                meta = CHECK_REGISTRY["IAM-004"]
                                findings.append(Finding(
                                    check_id="IAM-004",
                                    service=meta["service"],
                                    resource=policy["PolicyArn"],
                                    severity=Severity[meta["severity"]],
                                    title=meta["title"],
                                    description=f"Customer managed policy '{policy['PolicyName']}' attached to Role '{rname}' allows wildcard '*' actions or resources.",
                                    recommendation=meta["recommendation"],
                                    reference=meta["reference"],
                                    cis_control=meta["cis_control"]
                                ))
                                break
            except ClientError as e:
                logger.error(f"Error checking role policies for {rname}: {str(e)}")

            # IAM-004: Inline Policies
            try:
                inline_policies = client.list_role_policies(RoleName=rname).get("PolicyNames", [])
                for pname in inline_policies:
                    p_doc = client.get_role_policy(RoleName=rname, PolicyName=pname)["PolicyDocument"]
                    statements = p_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if check_wildcard_statement(stmt):
                            meta = CHECK_REGISTRY["IAM-004"]
                            findings.append(Finding(
                                check_id="IAM-004",
                                service=meta["service"],
                                resource=f"{rarn}/policy/{pname}",
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"Role '{rname}' inline policy '{pname}' allows wildcard '*' actions or resources.",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"]
                            ))
                            break
            except ClientError as e:
                logger.error(f"Error checking role inline policies for {rname}: {str(e)}")

    except ClientError as e:
        logger.error(f"Failed to list IAM roles: {str(e)}")

    return findings
