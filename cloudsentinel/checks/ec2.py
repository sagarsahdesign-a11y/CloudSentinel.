import logging
from typing import List
from botocore.exceptions import ClientError

from cloudsentinel.models import Finding, Severity, CHECK_REGISTRY
from cloudsentinel.utils import get_aws_client

logger = logging.getLogger("cloudsentinel.checks.ec2")

def run_checks(session, account_id: str, regions: List[str]) -> List[Finding]:
    """Runs all EC2-related security checks across specified regions."""
    findings = []
    
    # Legacy instance families (prefixes)
    LEGACY_PREFIXES = ("t1.", "t2.", "m1.", "m2.", "m3.", "c1.", "c3.", "r3.", "g2.", "i2.")

    for region in regions:
        client = get_aws_client(session, "ec2", region_name=region)
        
        # --- Check default account EBS encryption settings in this region ---
        try:
            ebs_default = client.get_ebs_encryption_by_default()
            if not ebs_default.get("EbsEncryptionByDefault", False):
                meta = CHECK_REGISTRY["EC2-003"]
                findings.append(Finding(
                    check_id="EC2-003",
                    service=meta["service"],
                    resource=f"arn:aws:ec2:{region}:{account_id}:ebs-encryption-settings",
                    severity=Severity[meta["severity"]],
                    title=meta["title"],
                    description=f"EBS encryption by default is disabled in region {region}.",
                    recommendation=meta["recommendation"],
                    reference=meta["reference"],
                    cis_control=meta["cis_control"],
                    region=region
                ))
        except ClientError as e:
            logger.error(f"Error checking default EBS encryption in region {region}: {str(e)}")

        # --- Scan EC2 instances ---
        try:
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                        state = instance.get("State", {}).get("Name")
                        
                        # Skip terminated instances
                        if state == "terminated":
                            continue

                        # EC2-001: Public IP exposure
                        public_ip = instance.get("PublicIpAddress")
                        if public_ip:
                            meta = CHECK_REGISTRY["EC2-001"]
                            findings.append(Finding(
                                check_id="EC2-001",
                                service=meta["service"],
                                resource=instance_arn,
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"EC2 instance '{instance_id}' has a public IP address {public_ip} associated.",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"],
                                region=region
                            ))

                        # EC2-002: IMDSv2 disabled
                        metadata_options = instance.get("MetadataOptions", {})
                        http_tokens = metadata_options.get("HttpTokens")
                        if http_tokens != "required":
                            meta = CHECK_REGISTRY["EC2-002"]
                            findings.append(Finding(
                                check_id="EC2-002",
                                service=meta["service"],
                                resource=instance_arn,
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"EC2 instance '{instance_id}' has IMDSv2 disabled (IMDSv1 allowed/optional).",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"],
                                region=region
                            ))

                        # EC2-004: Legacy Instance Type
                        instance_type = instance.get("InstanceType", "")
                        if instance_type.startswith(LEGACY_PREFIXES):
                            meta = CHECK_REGISTRY["EC2-004"]
                            findings.append(Finding(
                                check_id="EC2-004",
                                service=meta["service"],
                                resource=instance_arn,
                                severity=Severity[meta["severity"]],
                                title=meta["title"],
                                description=f"EC2 instance '{instance_id}' is running on outdated instance family '{instance_type}'.",
                                recommendation=meta["recommendation"],
                                reference=meta["reference"],
                                cis_control=meta["cis_control"],
                                region=region
                            ))
        except ClientError as e:
            logger.error(f"Error checking EC2 instances in region {region}: {str(e)}")

        # --- Scan EBS volumes ---
        try:
            paginator = client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    volume_id = volume["VolumeId"]
                    volume_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"
                    
                    if not volume.get("Encrypted", False):
                        meta = CHECK_REGISTRY["EC2-003"]
                        findings.append(Finding(
                            check_id="EC2-003",
                            service=meta["service"],
                            resource=volume_arn,
                            severity=Severity[meta["severity"]],
                            title=meta["title"],
                            description=f"EBS volume '{volume_id}' is not encrypted.",
                            recommendation=meta["recommendation"],
                            reference=meta["reference"],
                            cis_control=meta["cis_control"],
                            region=region
                        ))
        except ClientError as e:
            logger.error(f"Error checking EBS volumes in region {region}: {str(e)}")

    return findings
