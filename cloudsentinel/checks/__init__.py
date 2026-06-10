from .iam import run_checks as run_iam_checks
from .s3 import run_checks as run_s3_checks
from .ec2 import run_checks as run_ec2_checks
from .security_groups import run_checks as run_sg_checks
from .cloudtrail import run_checks as run_cloudtrail_checks
from .mfa import run_checks as run_mfa_checks

ALL_CHECK_FUNCTIONS = [
    run_iam_checks,
    run_s3_checks,
    run_ec2_checks,
    run_sg_checks,
    run_cloudtrail_checks,
    run_mfa_checks
]
