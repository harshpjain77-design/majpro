"""Threat detection rules package."""

from backend.detection.rules.base import BaseRule
from backend.detection.rules.rule_001_brute_force import SingleSourceBruteForceRule
from backend.detection.rules.rule_002_failed_then_success import FailedFollowedBySuccessRule
from backend.detection.rules.rule_003_password_spray import DistributedPasswordSprayRule
from backend.detection.rules.rule_004_privileged_activity import PrivilegedActivityRule
from backend.detection.rules.rule_005_suspicious_sequence import SuspiciousAuthenticationSequenceRule

__all__ = [
    "BaseRule",
    "SingleSourceBruteForceRule",
    "FailedFollowedBySuccessRule",
    "DistributedPasswordSprayRule",
    "PrivilegedActivityRule",
    "SuspiciousAuthenticationSequenceRule",
]
