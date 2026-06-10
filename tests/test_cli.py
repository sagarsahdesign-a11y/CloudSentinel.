from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from cloudsentinel.cli import app
from cloudsentinel.models import ScanResult, ScanMetadata, Finding, Severity

runner = CliRunner()

def test_explain_valid_check():
    res = runner.invoke(app, ["explain", "S3-001"])
    assert res.exit_code == 0
    assert "S3-001" in res.stdout
    assert "Public Buckets" in res.stdout
    assert "Remediation" in res.stdout

def test_explain_invalid_check():
    res = runner.invoke(app, ["explain", "INVALID-ID"])
    assert res.exit_code == 1
    assert "INVALID-ID" in res.stdout
    assert "not found" in res.stdout

@patch("cloudsentinel.cli.scanner.scan")
@patch("cloudsentinel.cli.reporter.write_report")
def test_scan_command_outputs(mock_write_report, mock_scan):
    # Mock scan results
    metadata = ScanMetadata(
        timestamp="2026-06-10T12:00:00Z",
        aws_account_id="999999999999",
        regions_scanned=["us-east-1"]
    )
    result = ScanResult(
        metadata=metadata,
        findings=[],
        category_scores={"IAM": 100, "S3": 100, "EC2": 100, "Network": 100, "CloudTrail": 100, "MFA": 100},
        overall_score=100,
        severity_summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )
    mock_scan.return_value = result
    
    # Run scan CLI command
    res = runner.invoke(app, ["scan", "--profile", "test-profile", "--format", "json", "--output", "reports_dir"])
    assert res.exit_code == 0
    assert "Scan executive summary" in res.stdout or "Scan Executive Summary" in res.stdout
    assert "100/100" in res.stdout
    assert mock_scan.called
    assert mock_write_report.called
