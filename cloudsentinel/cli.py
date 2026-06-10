import os
import logging
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown

from cloudsentinel import scanner, reporter, utils
from cloudsentinel.models import CHECK_REGISTRY, Finding, Severity

logger = logging.getLogger("cloudsentinel.cli")

app = typer.Typer(
    name="cloudsentinel",
    help="CloudSentinel: Production-grade AWS Cloud Misconfiguration Scanner",
    add_completion=False
)

console = Console()

def get_severity_color(sev: str) -> str:
    s = sev.upper()
    if s == "CRITICAL":
        return "red"
    elif s == "HIGH":
        return "orange3"
    elif s == "MEDIUM":
        return "yellow"
    elif s == "LOW":
        return "blue"
    else:
        return "grey50"

def print_banner():
    banner = r"""
  [bold indigo] _____ _                 _ _____            _   _             _ [/bold indigo]
 [bold indigo]/  __ \ |               | /  ___|          | | (_)           | |[/bold indigo]
 [bold indigo]| /  \/ | ___  _   _  __| \ `--.  ___ _ __ | |_ _ _ __   ___| |[/bold indigo]
 [bold indigo]| |   | |/ _ \| | | |/ _` |`--. \/ _ \ '_ \| __| | '_ \ / _ \ |[/bold indigo]
 [bold indigo]| \__/\ | (_) | |_| | (_| /\__/ /  __/ | | | |_| | | | |  __/ |[/bold indigo]
 [bold indigo] \____/_|\___/ \__,_|\__,_\____/ \___|_| |_|\__|_|_| |_|\___|_|[/bold indigo]
    """
    console.print(banner)
    console.print("[dim]AWS Cloud Misconfiguration Scanner & Auditor[/dim]", justify="center")
    console.print("[dim]Version 1.0.0 | CIS AWS Foundations Benchmarks[/dim]\n", justify="center")

@app.command()
def scan(
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p",
        help="AWS credentials profile name to authenticate with"
    ),
    regions: Optional[str] = typer.Option(
        None, "--regions", "-r",
        help="Comma-separated list of regions to scan (e.g. us-east-1,us-west-2)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Directory or file path to write the scan reports"
    ),
    format: List[str] = typer.Option(
        ["json"], "--format", "-f",
        help="Output formats (json, html, csv, sarif). Can be repeated for multiple outputs."
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity level to display (CRITICAL, HIGH, MEDIUM, LOW, INFO)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose debug logging outputs"
    )
):
    """
    Scan AWS credentials/environments for security misconfigurations.
    """
    utils.setup_logging(verbose=verbose)
    print_banner()

    # 1. Parse Inputs
    # Parse regions
    region_list = None
    if regions:
        region_list = [r.strip() for r in regions.split(",") if r.strip()]

    # Validate formats
    valid_formats = {"json", "html", "csv", "sarif"}
    requested_formats = []
    for fmt in format:
        for f in fmt.split(","):
            f_clean = f.strip().lower()
            if f_clean not in valid_formats:
                console.print(f"[bold red]Error:[/] Invalid format '{f_clean}'. Supported: json, html, csv, sarif.")
                raise typer.Exit(code=1)
            requested_formats.append(f_clean)

    # Validate severity
    min_severity = None
    if severity:
        sev_clean = severity.strip().upper()
        try:
            min_severity = Severity[sev_clean]
        except KeyError:
            console.print(f"[bold red]Error:[/] Invalid severity '{severity}'. Supported: CRITICAL, HIGH, MEDIUM, LOW, INFO.")
            raise typer.Exit(code=1)

    # 2. Run Scan with dynamic progress indicators
    result = None
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Configuring AWS environment...", total=100)
        
        def update_progress(msg: str):
            progress.update(task, description=f"[bold cyan]{msg}[/bold cyan]")
            
        try:
            result = scanner.scan(profile=profile, regions=region_list, status_callback=update_progress)
            progress.update(task, completed=100, description="[bold green]Scan completed successfully![/bold green]")
        except Exception as e:
            progress.update(task, description="[bold red]Scan failed![/bold red]")
            console.print(f"\n[bold red]Error running scan:[/] {str(e)}")
            raise typer.Exit(code=1)

    # 3. Filter findings if requested
    filtered_findings = result.findings
    if min_severity:
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        min_rank = severity_order[min_severity]
        filtered_findings = [f for f in result.findings if severity_order[f.severity] >= min_rank]

    # 4. Render Terminal Dashboard
    console.print("\n")
    
    score = result.overall_score
    score_col = "green" if score >= 90 else ("blue" if score >= 75 else ("yellow" if score >= 60 else "red"))
    score_panel = Panel(
        f"\n  [bold]Cloud Security Score[/bold]\n\n         [bold {score_col} size=24]{score}/100[/]\n",
        title="Score",
        expand=False,
        border_style=score_col,
        width=30
    )

    # Category breakdown table
    cat_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    cat_table.add_column("Category")
    cat_table.add_column("Score", justify="right")
    for cat, cat_score in result.category_scores.items():
        color = "green" if cat_score >= 90 else ("blue" if cat_score >= 75 else ("yellow" if cat_score >= 60 else "red"))
        cat_table.add_row(cat, f"[{color}]{cat_score}[/]")

    # Severity counters panel
    sev_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    sev_table.add_row("[red]CRITICAL[/]", str(result.severity_summary["CRITICAL"]))
    sev_table.add_row("[orange3]HIGH[/]", str(result.severity_summary["HIGH"]))
    sev_table.add_row("[yellow]MEDIUM[/]", str(result.severity_summary["MEDIUM"]))
    sev_table.add_row("[blue]LOW[/]", str(result.severity_summary["LOW"]))
    sev_table.add_row("[grey50]INFO[/]", str(result.severity_summary["INFO"]))

    summary_cols = Columns([score_panel, cat_table, sev_table])
    console.print(Panel(summary_cols, title="[bold]Scan Executive Summary[/bold]", expand=False))
    console.print("\n")

    # Display Findings Table
    findings_table = Table(title=f"Findings List (Showing {len(filtered_findings)} of {len(result.findings)} items)", show_header=True, header_style="bold white")
    findings_table.add_column("ID", style="bold cyan", width=10)
    findings_table.add_column("Category", style="magenta", width=12)
    findings_table.add_column("Severity", justify="center", width=12)
    findings_table.add_column("Resource", style="green", width=30)
    findings_table.add_column("Title", style="bold")
    findings_table.add_column("CIS", style="dim", justify="center", width=8)

    for f in filtered_findings:
        col = get_severity_color(f.severity.value)
        # Severity Badge
        badge = f"[bold white on {col}] {f.severity.value[:8].center(8)} [/]"
        
        # Shorten resource if too long
        res_display = f.resource
        if len(res_display) > 30:
            res_display = "..." + res_display[-27:]
            
        findings_table.add_row(
            f.check_id,
            f.service,
            badge,
            res_display,
            f.title,
            f.cis_control
        )

    console.print(findings_table)
    console.print("\n[dim]* Note: Run 'cloudsentinel explain <CHECK_ID>' to see detailed remediation advice for any finding ID.[/dim]\n")

    # 5. Write Report Files
    if output:
        # Determine path structure
        # If output is a directory, generate default filenames for each requested format.
        # If output is a specific file, check if single format and write directly.
        is_dir = os.path.isdir(output) or (not os.path.exists(output) and not output.endswith((".json", ".html", ".csv", ".sarif")))
        
        for fmt in requested_formats:
            if is_dir:
                filename = f"cloudsentinel_report_{result.metadata.aws_account_id}.{fmt}"
                file_path = os.path.join(output, filename)
            else:
                file_path = output

            # Generate report content
            if fmt == "json":
                content = reporter.generate_json_report(result)
            elif fmt == "html":
                content = reporter.generate_html_report(result)
            elif fmt == "csv":
                content = reporter.generate_csv_report(result)
            elif fmt == "sarif":
                content = reporter.generate_sarif_report(result)
            else:
                continue

            reporter.write_report(content, file_path)
            console.print(f"[bold green][+][/bold green] Wrote {fmt.upper()} report to: [cyan]{file_path}[/cyan]")
    else:
        # If no output specified, write default JSON and HTML reports in the current directory
        # to ensure the user always has access to the comprehensive outputs!
        try:
            curr_dir = os.getcwd()
            json_path = os.path.join(curr_dir, f"cloudsentinel_report_{result.metadata.aws_account_id}.json")
            html_path = os.path.join(curr_dir, f"cloudsentinel_report_{result.metadata.aws_account_id}.html")
            
            reporter.write_report(reporter.generate_json_report(result), json_path)
            reporter.write_report(reporter.generate_html_report(result), html_path)
            
            console.print(f"[bold green][+][/bold green] Wrote default JSON report: [cyan]{json_path}[/cyan]")
            console.print(f"[bold green][+][/bold green] Wrote default HTML report: [cyan]{html_path}[/cyan]")
        except Exception as e:
            logger.debug(f"Could not write default reports in local directory: {str(e)}")

@app.command()
def explain(
    check_id: str = typer.Argument(
        ...,
        help="The security check ID to explain (e.g. S3-001)"
    )
):
    """
    Explain a security check finding and show detailed remediation instructions.
    """
    cid_upper = check_id.strip().upper()
    if cid_upper not in CHECK_REGISTRY:
        console.print(f"[bold red]Error:[/] Check ID '{check_id}' not found in CloudSentinel registry.")
        raise typer.Exit(code=1)

    meta = CHECK_REGISTRY[cid_upper]
    sev = meta["severity"]
    col = get_severity_color(sev)

    markdown_content = f"""
# {cid_upper}: {meta['title']}

**AWS Service**: {meta['service']}
**Severity**: {sev}
**CIS Foundations Control**: {meta['cis_control']}

## Description
{meta['description']}

## Remediation & Mitigation Guidance
{meta['recommendation']}

## Reference Documentation
{meta['reference']}
"""

    panel = Panel(
        Markdown(markdown_content),
        title=f"[bold]Check Specification: {cid_upper}[/bold]",
        border_style=col,
        expand=False
    )
    console.print(panel)

if __name__ == "__main__":
    app()
