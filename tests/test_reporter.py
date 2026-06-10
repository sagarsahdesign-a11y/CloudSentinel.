import os
import json
import pytest
from datetime import datetime, timezone

from cloudsentinel.models import ScanResult, ScanMetadata, Finding, Severity
from cloudsentinel import reporter

@pytest.fixture
def mock_scan_result():
    metadata = ScanMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        aws_account_id="123456789012",
        regions_scanned=["us-east-1"],
        aws_profile="dev"
    )
    finding = Finding(
        check_id="S3-001",
        service="S3",
        resource="arn:aws:s3:::my-bucket",
        severity=Severity.CRITICAL,
        title="Public Bucket",
        description="Public S3 bucket exposed",
        recommendation="Enable Block Public Access",
        reference="https://docs.aws.amazon.com/S3/security.html",
        cis_control="2.1.1",
        region="us-east-1"
    )
    return ScanResult(
        metadata=metadata,
        findings=[finding],
        category_scores={"IAM": 100, "S3": 85, "EC2": 100, "Network": 100, "CloudTrail": 100, "MFA": 100},
        overall_score=98,
        severity_summary={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )

def test_json_reporter(mock_scan_result):
    report = reporter.generate_json_report(mock_scan_result)
    data = json.loads(report)
    assert data["overall_score"] == 98
    assert data["metadata"]["aws_account_id"] == "123456789012"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["check_id"] == "S3-001"

def test_csv_reporter(mock_scan_result):
    report = reporter.generate_csv_report(mock_scan_result)
    lines = report.strip().split("\n")
    assert len(lines) == 2  # Header + 1 row
    assert "S3-001" in lines[1]
    assert "arn:aws:s3:::my-bucket" in lines[1]
    assert "CRITICAL" in lines[1]

def test_html_reporter(mock_scan_result):
    report = reporter.generate_html_report(mock_scan_result)
    assert "<!DOCTYPE html>" in report
    assert "CloudSentinel Audit Report" in report
    assert "123456789012" in report
    assert "my-bucket" in report
    assert "2.1.1" in report

def test_sarif_reporter(mock_scan_result):
    report = reporter.generate_sarif_report(mock_scan_result)
    data = json.loads(report)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "CloudSentinel"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "S3-001"
    assert run["results"][0]["level"] == "error"
