import pytest
import boto3
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from moto import mock_aws

from cloudsentinel.models import Severity
from cloudsentinel.checks import iam, s3, ec2, security_groups, cloudtrail, mfa

@pytest.fixture
def aws_session():
    return boto3.Session(region_name="us-east-1")

# --- IAM Checks Tests ---
@mock_aws
def test_iam_checks_no_findings(aws_session):
    # Setup IAM and STS
    client = aws_session.client("iam", region_name="us-east-1")
    
    # Mock credential report retrieval helper to return an empty report or one with active MFA/recent usage
    csv_content = (
        "user,arn,user_creation_time,password_active,password_last_used,"
        "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,mfa_active\n"
        "test-user,arn:aws:iam::123456789012:user/test-user,2026-06-01T00:00:00Z,true,2026-06-09T00:00:00Z,"
        "false,N/A,N/A,false,N/A,N/A,true\n"
    )
    
    with patch("cloudsentinel.checks.iam.get_credential_report", return_value=csv_content):
        findings = iam.run_checks(aws_session, "123456789012", ["us-east-1"])
        
        # Should be 0 findings because the user has active password used recently and has MFA
        assert len([f for f in findings if f.check_id in ("IAM-001", "IAM-002")]) == 0

@mock_aws
def test_iam_checks_with_findings(aws_session):
    client = aws_session.client("iam", region_name="us-east-1")
    
    # User inactive for > 90 days, access key older than 90 days
    csv_content = (
        "user,arn,user_creation_time,password_active,password_last_used,"
        "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,mfa_active\n"
        "inactive-user,arn:aws:iam::123456789012:user/inactive-user,2025-01-01T00:00:00Z,true,2025-02-01T00:00:00Z,"
        "true,2025-01-01T00:00:00Z,2025-02-01T00:00:00Z,false,N/A,N/A,false\n"
    )
    
    client.create_user(UserName="inactive-user")
    
    with patch("cloudsentinel.checks.iam.get_aws_client", return_value=client):
        with patch("cloudsentinel.checks.iam.get_credential_report", return_value=csv_content):
            with patch.object(client, "list_attached_user_policies") as mock_attached:
                mock_attached.return_value = {
                    "AttachedPolicies": [
                        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                    ]
                }
                with patch.object(client, "list_user_policies") as mock_inline:
                    mock_inline.return_value = {"PolicyNames": ["wildcard-inline"]}
                    with patch.object(client, "get_user_policy") as mock_get_inline:
                        mock_get_inline.return_value = {
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                            }
                        }
                        findings = iam.run_checks(aws_session, "123456789012", ["us-east-1"])
                        
                        # Verify inactive user finding
                        inactive_findings = [f for f in findings if f.check_id == "IAM-001"]
                        assert len(inactive_findings) == 1
                        assert inactive_findings[0].severity == Severity.MEDIUM
                        
                        # Verify access key age finding
                        key_findings = [f for f in findings if f.check_id == "IAM-002"]
                        assert len(key_findings) == 1
                        
                        # Verify AdminAccess finding
                        admin_findings = [f for f in findings if f.check_id == "IAM-003"]
                        assert len(admin_findings) == 1
                        assert admin_findings[0].severity == Severity.HIGH
                        
                        # Verify Wildcard finding
                        wildcard_findings = [f for f in findings if f.check_id == "IAM-004"]
                        assert len(wildcard_findings) == 1
                        assert wildcard_findings[0].severity == Severity.HIGH

# --- S3 Checks Tests ---
@mock_aws
def test_s3_checks_findings(aws_session):
    s3_client = aws_session.client("s3", region_name="us-east-1")
    
    bucket_name = "test-insecure-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    
    # We do NOT set public access block, versioning, default encryption or logging
    findings = s3.run_checks(aws_session, "123456789012", ["us-east-1"])
    
    check_ids = [f.check_id for f in findings]
    assert "S3-001" in check_ids  # Public Buckets (no BPA)
    assert "S3-003" in check_ids  # Missing default encryption
    assert "S3-004" in check_ids  # Missing Versioning
    assert "S3-005" in check_ids  # Missing Logging

# --- EC2 Checks Tests ---
@mock_aws
def test_ec2_checks_findings(aws_session):
    ec2_client = aws_session.client("ec2", region_name="us-east-1")
    
    # Start a mock instance (IMDSv2 disabled by default, legacy t2.micro, has public IP if configured)
    reservation = ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        MetadataOptions={"HttpTokens": "optional"}
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    
    # Mock default EBS encryption to be false
    with patch("botocore.client.BaseClient._make_api_call") as mock_api:
        def side_effect(api_name, api_params):
            if api_name == "GetEbsEncryptionByDefault":
                return {"EbsEncryptionByDefault": False}
            elif api_name == "DescribeInstances":
                return {
                    "Reservations": [{
                        "Instances": [{
                            "InstanceId": instance_id,
                            "InstanceArn": f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}",
                            "State": {"Name": "running"},
                            "PublicIpAddress": "54.123.45.67",
                            "MetadataOptions": {"HttpTokens": "optional"},
                            "InstanceType": "t2.micro"
                        }]
                    }]
                }
            elif api_name == "DescribeVolumes":
                return {
                    "Volumes": [{
                        "VolumeId": "vol-12345678",
                        "Encrypted": False
                    }]
                }
            # Fallback to default mock behaviour or ClientError
            raise ClientError({"Error": {"Code": "Unknown", "Message": "Mocked failure"}}, api_name)
            
        mock_api.side_effect = side_effect
        findings = ec2.run_checks(aws_session, "123456789012", ["us-east-1"])
        
        check_ids = [f.check_id for f in findings]
        assert "EC2-001" in check_ids  # Public IP exposure
        assert "EC2-002" in check_ids  # IMDSv2 disabled
        assert "EC2-003" in check_ids  # EBS Encryption default setting/volume
        assert "EC2-004" in check_ids  # Legacy instance type

# --- Security Group Checks Tests ---
@mock_aws
def test_security_group_checks_findings(aws_session):
    ec2_client = aws_session.client("ec2", region_name="us-east-1")
    
    # Get the default security group
    res = ec2_client.describe_security_groups()
    default_sg_id = res["SecurityGroups"][0]["GroupId"]
    
    # Authorize SSH (22), RDP (3389), database ports open to 0.0.0.0/0
    ec2_client.authorize_security_group_ingress(
        GroupId=default_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    
    findings = security_groups.run_checks(aws_session, "123456789012", ["us-east-1"])
    
    check_ids = [f.check_id for f in findings]
    assert "SG-001" in check_ids  # SSH exposed
    assert "SG-002" in check_ids  # RDP exposed
    assert "SG-003" in check_ids  # DB exposed (Postgres)
    assert "SG-005" in check_ids  # Egress open (default egress rules permit all outbound)

# --- CloudTrail Checks Tests ---
@mock_aws
def test_cloudtrail_checks_findings(aws_session):
    # Test CloudTrail disabled
    findings = cloudtrail.run_checks(aws_session, "123456789012", ["us-east-1"])
    check_ids = [f.check_id for f in findings]
    assert "CT-001" in check_ids  # Disabled

# --- MFA Checks Tests ---
@mock_aws
def test_mfa_checks_findings(aws_session):
    # Test Root MFA disabled and user without MFA
    csv_content = (
        "user,arn,mfa_active\n"
        "nomfa-user,arn:aws:iam::123456789012:user/nomfa-user,false\n"
    )
    
    with patch("cloudsentinel.checks.mfa.get_credential_report", return_value=csv_content):
        findings = mfa.run_checks(aws_session, "123456789012", ["us-east-1"])
        
        check_ids = [f.check_id for f in findings]
        assert "MFA-001" in check_ids  # Root MFA Disabled (get_account_summary returns 0 in mock)
        assert "MFA-002" in check_ids  # IAM User without MFA
