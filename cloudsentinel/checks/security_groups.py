import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client

logger = logging.getLogger("cloudsentinel.checks.security_groups")

# Database ports we want to check for internet exposure
DB_PORTS = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached"
}

def is_open_to_internet(ip_permission: Dict[str, Any]) -> bool:
    """Checks if the rule allows ingress from 0.0.0.0/0 or ::/0."""
    for ip_range in ip_permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            return True
    for ipv6_range in ip_permission.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            return True
    return False

def exposes_port(ip_permission: Dict[str, Any], target_port: int) -> bool:
    """Checks if the rule exposes a specific target port."""
    protocol = ip_permission.get("IpProtocol")
    
    # Protocol "-1" means all protocols/ports are exposed
    if protocol == "-1":
        return True
        
    if protocol in ("tcp", "udp"):
        from_port = ip_permission.get("FromPort")
        to_port = ip_permission.get("ToPort")
        if from_port is not None and to_port is not None:
            return from_port <= target_port <= to_port
            
    return False

def count_rules(permissions: List[Dict[str, Any]]) -> int:
    """Counts the effective number of rules in a permission list."""
    count = 0
    for perm in permissions:
        # Sum up all targets (IPs, SGs, Prefix lists)
        count += len(perm.get("IpRanges", []))
        count += len(perm.get("Ipv6Ranges", []))
        count += len(perm.get("UserIdGroupPairs", []))
        count += len(perm.get("PrefixListIds", []))
        # If the permission exists but has no targets (unlikely in parsed SG rules)
        if not (perm.get("IpRanges") or perm.get("Ipv6Ranges") or perm.get("UserIdGroupPairs") or perm.get("PrefixListIds")):
            count += 1
    return count

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all Security Group checks across specified regions."""
    findings = []
    
    for region in regions:
        client = get_aws_client(session, "ec2", region_name=region)
        
        try:
            paginator = client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    sg_arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                    
                    ip_permissions = sg.get("IpPermissions", [])
                    ip_permissions_egress = sg.get("IpPermissionsEgress", [])
                    
                    # --- SG-001: SSH Open to Internet ---
                    # --- SG-002: RDP Open to Internet ---
                    # --- SG-003: Database Ports Exposed ---
                    for perm in ip_permissions:
                        if is_open_to_internet(perm):
                            # Check SSH (22)
                            if exposes_port(perm, 22):
                                meta = CHECK_REGISTRY["SG-001"]
                                findings.append(Finding(
                                    check_id="SG-001",
                                    service=meta["service"],
                                    resource=sg_arn,
                                    severity=Severity[meta["severity"]],
                                    title=meta["title"],
                                    description=f"Security Group '{sg_name}' ({sg_id}) allows inbound SSH (port 22) from the internet.",
                                    recommendation=meta["recommendation"],
                                    reference=meta["reference"],
                                    cis_control=meta["cis_control"],
                                    region=region
                                ))
                            
                            # Check RDP (3389)
                            if exposes_port(perm, 3389):
                                meta = CHECK_REGISTRY["SG-002"]
                                findings.append(Finding(
                                    check_id="SG-002",
                                    service=meta["service"],
                                    resource=sg_arn,
                                    severity=Severity[meta["severity"]],
                                    title=meta["title"],
                                    description=f"Security Group '{sg_name}' ({sg_id}) allows inbound RDP (port 3389) from the internet.",
                                    recommendation=meta["recommendation"],
                                    reference=meta["reference"],
                                    cis_control=meta["cis_control"],
                                    region=region
                                ))
                                
                            # Check DB ports
                            for db_port, db_name in DB_PORTS.items():
                                if exposes_port(perm, db_port):
                                    meta = CHECK_REGISTRY["SG-003"]
                                    findings.append(Finding(
                                        check_id="SG-003",
                                        service=meta["service"],
                                        resource=sg_arn,
                                        severity=Severity[meta["severity"]],
                                        title=meta["title"],
                                        description=f"Security Group '{sg_name}' ({sg_id}) allows inbound database port {db_port} ({db_name}) from the internet.",
                                        recommendation=meta["recommendation"],
                                        reference=meta["reference"],
                                        cis_control=meta["cis_control"],
                                        region=region
                                    ))

                    # --- SG-004: Excessive Rules ---
                    inbound_count = count_rules(ip_permissions)
                    outbound_count = count_rules(ip_permissions_egress)
                    
                    if inbound_count > 30 or outbound_count > 30:
                        meta = CHECK_REGISTRY["SG-004"]
                        findings.append(Finding(
                            check_id="SG-004",
                            service=meta["service"],
                            resource=sg_arn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"Security Group '{sg_name}' ({sg_id}) contains excessive rules (Inbound: {inbound_count}, Outbound: {outbound_count}). Limit is 30 rules.",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"],
                            region=region
                        ))

                    # --- SG-005: Unrestricted Outbound Access ---
                    has_unrestricted_outbound = False
                    for perm in ip_permissions_egress:
                        # Protocol -1 (all) or all ports, open to 0.0.0.0/0 or ::/0
                        if perm.get("IpProtocol") == "-1" and is_open_to_internet(perm):
                            has_unrestricted_outbound = True
                            break
                            
                    if has_unrestricted_outbound:
                        meta = CHECK_REGISTRY["SG-005"]
                        findings.append(Finding(
                            check_id="SG-005",
                            service=meta["service"],
                            resource=sg_arn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"Security Group '{sg_name}' ({sg_id}) allows unrestricted outbound traffic (egress to 0.0.0.0/0 on all protocols).",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"],
                            region=region
                        ))
        except ClientError as e:
            logger.error(f"Error checking Security Groups in region {region}: {str(e)}")

    return findings
