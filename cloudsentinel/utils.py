import logging
import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from typing import List, Dict, Tuple, Optional
from cloudsentinel.models import Finding, Severity

# Initialize logger
logger = logging.getLogger("cloudsentinel")

def setup_logging(verbose: bool = False) -> None:
    """Configures the global logger level and handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )
    logger.setLevel(level)

def get_boto3_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    """Creates a boto3 session handling profiles and regions."""
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        return session
    except Exception as e:
        logger.error(f"Failed to create boto3 Session: {str(e)}")
        raise e

def get_aws_client(session: boto3.Session, service_name: str, region_name: Optional[str] = None):
    """Creates a service client with production-grade retry configuration (botocore standard retries)."""
    retry_config = Config(
        retries={
            "max_attempts": 5,
            "mode": "standard"  # standard includes rate limit retries
        }
    )
    return session.client(service_name, region_name=region_name, config=retry_config)

def calculate_scores(findings: List[Finding]) -> Tuple[Dict[str, int], int]:
    """
    Calculates category-specific and overall security scores.
    Weights: Critical = 15, High = 8, Medium = 4, Low = 1, Info = 0
    Category score: max(0, 100 - sum(findings in category * weight))
    Overall score: average of all 6 category scores.
    """
    weights = {
        Severity.CRITICAL: 15,
        Severity.HIGH: 8,
        Severity.MEDIUM: 4,
        Severity.LOW: 1,
        Severity.INFO: 0
    }
    
    categories = ["IAM", "S3", "EC2", "Network", "CloudTrail", "MFA"]
    category_scores = {cat: 100 for cat in categories}
    category_deductions = {cat: 0 for cat in categories}
    
    for finding in findings:
        weight = weights.get(finding.severity, 0)
        # Map finding service to scoring category
        # If finding service is 'Network', it directly maps to Network.
        service_cat = finding.service
        if service_cat in category_scores:
            category_deductions[service_cat] += weight
        else:
            # Fallback or mapping
            logger.warning(f"Finding service '{service_cat}' not in scoring categories. Ignoring in score calculation.")
            
    for cat in categories:
        score = 100 - category_deductions[cat]
        category_scores[cat] = max(0, score)
        
    overall_score = round(sum(category_scores.values()) / len(categories))
    return category_scores, overall_score
