"""Safety guardrails, target allowlists, and execution rate-limiting for response actions."""

import ipaddress
import re
import time
from typing import Dict, List, Optional, Tuple
from backend.response.config import ResponseConfig
from backend.response.schemas import ActionType


class SafetyGuard:
    """Enforces strict allowlists, command injection sanitization, and action throttling."""

    # Disallowed characters in target strings that could attempt command injection
    INJECTION_PATTERN = re.compile(r'[\x00\r\n;&|`$><]')

    def __init__(self, config: Optional[ResponseConfig] = None):
        self.config = config or ResponseConfig()
        # In-memory sliding window history: target -> list of timestamps
        self._target_action_history: Dict[str, List[float]] = {}

    def is_protected_ip(self, ip_str: str) -> bool:
        """Check whether an IP address is protected by allowlist or loopback/link-local invariants."""
        ip_clean = ip_str.strip().lower()
        if ip_clean in self.config.protected_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            # Loopback addresses (127.0.0.0/8, ::1)
            if ip_obj.is_loopback:
                return True
            # Link local addresses
            if ip_obj.is_link_local:
                return True
            # Unspecified (0.0.0.0)
            if ip_obj.is_unspecified:
                return True
        except ValueError:
            # Not a valid IP object; could be a hostname
            if ip_clean in {"localhost", "127.0.0.1", "::1"}:
                return True

        return False

    def is_protected_user(self, username: str) -> bool:
        """Check whether a username is a protected critical administrative or service account."""
        user_clean = username.strip().lower()
        return user_clean in self.config.protected_users

    def validate_target(self, action_type: ActionType, target: str) -> Tuple[bool, Optional[str]]:
        """Validate target against allowlists and character sanitization invariants.
        
        Returns:
            (is_valid: bool, error_reason: Optional[str])
        """
        if not target or not target.strip():
            return False, "Target identifier cannot be empty."

        clean_target = target.strip()

        # 1. Command injection character defense
        if self.INJECTION_PATTERN.search(clean_target):
            return False, f"Target '{clean_target}' contains disallowed characters (possible injection attack)."

        # 2. IP Blocking Allowlist Check
        if action_type == ActionType.BLOCK_IP:
            if self.is_protected_ip(clean_target):
                return False, f"Target IP '{clean_target}' is in the protected allowlist and cannot be blocked."

        # 3. Account Locking Allowlist Check
        elif action_type == ActionType.LOCK_ACCOUNT:
            if self.is_protected_user(clean_target):
                return False, f"User account '{clean_target}' is in the protected allowlist and cannot be locked."

        # 4. Terminate session check
        elif action_type == ActionType.TERMINATE_SESSION:
            if self.is_protected_user(clean_target):
                return False, f"Active session for protected administrative user '{clean_target}' cannot be automatedly terminated."

        return True, None

    def check_rate_limit(self, target: str) -> Tuple[bool, Optional[str]]:
        """Check and enforce sliding-window action rate limits per target entity."""
        clean_target = target.strip().lower()
        now = time.time()
        window = 60.0  # 1 minute sliding window

        history = self._target_action_history.get(clean_target, [])
        # Prune older than 60 seconds
        history = [ts for ts in history if now - ts < window]
        self._target_action_history[clean_target] = history

        if len(history) >= self.config.max_actions_per_minute_per_target:
            return False, (
                f"Rate limit exceeded: target '{clean_target}' has reached the limit of "
                f"{self.config.max_actions_per_minute_per_target} actions per minute."
            )

        return True, None

    def record_action_executed(self, target: str) -> None:
        """Record an action execution timestamp for rate limiting."""
        clean_target = target.strip().lower()
        now = time.time()
        if clean_target not in self._target_action_history:
            self._target_action_history[clean_target] = []
        self._target_action_history[clean_target].append(now)
