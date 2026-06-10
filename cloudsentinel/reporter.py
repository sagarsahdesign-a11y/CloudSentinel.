import os
import csv
import json
import logging
from jinja2 import Environment, FileSystemLoader, Template

from cloudsentinel.models import ScanResult, CHECK_REGISTRY

logger = logging.getLogger("cloudsentinel.reporter")

def map_severity_to_sarif_level(severity: str) -> str:
    """Maps CloudSentinel severity to SARIF level (error, warning, note)."""
    val = severity.upper()
    if val in ("CRITICAL", "HIGH"):
        return "error"
    elif val == "MEDIUM":
        return "warning"
    else:
        return "note"

def generate_json_report(result: ScanResult) -> str:
    """Serializes scan results to a pretty-printed JSON string."""
    return result.model_dump_json(indent=2)

def generate_csv_report(result: ScanResult) -> str:
    """Converts findings list into a flat CSV string."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header row
    writer.writerow([
        "check_id", "service", "resource", "severity", "title",
        "description", "recommendation", "reference", "cis_control", "region"
    ])
    
    for finding in result.findings:
        writer.writerow([
            finding.check_id,
            finding.service,
            finding.resource,
            finding.severity.value,
            finding.title,
            finding.description,
            finding.recommendation,
            finding.reference,
            finding.cis_control,
            finding.region
        ])
        
    return output.getvalue()

def generate_html_report(result: ScanResult) -> str:
    """Renders scan results using the HTML Jinja2 template."""
    package_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(package_dir)
    
    # Try multiple paths for resolving template
    template_paths = [
        os.path.join(project_root, "templates", "report.html"),
        os.path.join(package_dir, "templates", "report.html"),
        "templates/report.html",
        "report.html"
    ]
    
    content = ""
    for path in template_paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            break
            
    if not content:
        raise FileNotFoundError("Could not find templates/report.html report template.")
        
    template = Template(content)
    return template.render(result=result)

def generate_sarif_report(result: ScanResult) -> str:
    """
    Generates an Oasis SARIF v2.1.0 report format.
    Useful for integration with GitHub security and code scanning tabs.
    """
    # 1. Define rules catalog in SARIF format
    sarif_rules = []
    for check_id, meta in CHECK_REGISTRY.items():
        # Remove spaces to make a rule name
        rule_name = "".join(x for x in meta["title"] if x.isalnum())
        sarif_rules.append({
            "id": check_id,
            "name": rule_name,
            "shortDescription": {
                "text": meta["title"]
            },
            "fullDescription": {
                "text": meta["description"]
            },
            "help": {
                "text": f"Remediation:\n{meta['recommendation']}\n\nReference: {meta['reference']}\nCIS Control: {meta['cis_control']}"
            },
            "properties": {
                "security-severity": "9.0" if meta["severity"] == "CRITICAL" else ("7.0" if meta["severity"] == "HIGH" else ("5.0" if meta["severity"] == "MEDIUM" else "2.0"))
            }
        })

    # 2. Define findings results
    sarif_results = []
    for finding in result.findings:
        level = map_severity_to_sarif_level(finding.severity.value)
        sarif_results.append({
            "ruleId": finding.check_id,
            "message": {
                "text": finding.description
            },
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.resource,
                            "description": {
                                "text": f"AWS Resource ({finding.service}) in region {finding.region}"
                            }
                        }
                    }
                }
            ]
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudSentinel",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/CloudSentinel",
                        "rules": sarif_rules
                    }
                },
                "results": sarif_results
            }
        ]
    }
    
    return json.dumps(sarif_data, indent=2)

def write_report(content: str, output_path: str) -> None:
    """Safely writes report content to a file, creating subdirectories if needed."""
    try:
        dir_name = os.path.dirname(output_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
            
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Successfully generated report file at {output_path}")
    except Exception as e:
        logger.error(f"Failed to write report file to {output_path}: {str(e)}")
        raise e
