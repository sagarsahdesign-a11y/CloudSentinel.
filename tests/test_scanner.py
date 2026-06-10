import pytest
from unittest.mock import patch, MagicMock
from cloudsentinel import scanner
from cloudsentinel.models import Finding, Severity

@patch("cloudsentinel.scanner.get_boto3_session")
@patch("cloudsentinel.scanner.get_aws_client")
def test_scan_orchestration_and_scoring(mock_get_client, mock_get_session):
    # Mock AWS client calls
    sts_mock = MagicMock()
    sts_mock.get_caller_identity.return_value = {"AccountId": "112233445566"}
    
    ec2_mock = MagicMock()
    ec2_mock.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
    
    def get_client_side_effect(session, service, region_name=None):
        if service == "sts":
            return sts_mock
        elif service == "ec2":
            return ec2_mock
        return MagicMock()
        
    mock_get_client.side_effect = get_client_side_effect
    
    # Mock check runner function outputs
    # Let's say IAM check yields 1 High finding, S3 yields 1 Critical finding.
    iam_finding = Finding(
        check_id="IAM-003",
        service="IAM",
        resource="arn:aws:iam::112233445566:user/admin",
        severity=Severity.HIGH,
        title="AdminAccess assigned",
        description="...",
        recommendation="...",
        reference="...",
        cis_control="1.16"
    )
    s3_finding = Finding(
        check_id="S3-001",
        service="S3",
        resource="arn:aws:s3:::public-bucket",
        severity=Severity.CRITICAL,
        title="Public Bucket",
        description="...",
        recommendation="...",
        reference="...",
        cis_control="2.1.1"
    )
    
    mock_iam_run = MagicMock(return_value=[iam_finding])
    mock_s3_run = MagicMock(return_value=[s3_finding])
    mock_other_run = MagicMock(return_value=[])
    
    mock_all_checks = [
        mock_iam_run,
        mock_s3_run,
        mock_other_run,
        mock_other_run,
        mock_other_run,
        mock_other_run
    ]
    
    scanner_patch = patch("cloudsentinel.scanner.ALL_CHECK_FUNCTIONS", mock_all_checks)
    scanner_patch.start()
        
    try:
        # Run scan
        result = scanner.scan(profile="test-profile")
        
        # Verify account identity and regions resolved
        assert result.metadata.aws_account_id == "112233445566"
        assert result.metadata.regions_scanned == ["us-east-1"]
        assert result.metadata.aws_profile == "test-profile"
        
        # Verify findings collected
        assert len(result.findings) == 2
        
        # Verify Scoring math:
        # Weights: Critical = 15, High = 8, Medium = 4, Low = 1, Info = 0
        # Category scores: max(0, 100 - sum(finding weight))
        # IAM: 100 - 8 (High) = 92
        # S3: 100 - 15 (Critical) = 85
        # Other categories (EC2, Network, CloudTrail, MFA): 100
        # Average: (92 + 85 + 100 + 100 + 100 + 100) / 6 = 577 / 6 = 96.16 => rounded: 96
        assert result.category_scores["IAM"] == 92
        assert result.category_scores["S3"] == 85
        assert result.category_scores["EC2"] == 100
        assert result.category_scores["Network"] == 100
        assert result.category_scores["CloudTrail"] == 100
        assert result.category_scores["MFA"] == 100
        
        assert result.overall_score == 96
        assert result.severity_summary["CRITICAL"] == 1
        assert result.severity_summary["HIGH"] == 1
        assert result.severity_summary["MEDIUM"] == 0
    finally:
        scanner_patch.stop()
