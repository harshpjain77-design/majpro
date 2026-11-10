"""Prompt injection sanitization and untrusted log boundary defense."""

import re
from typing import List, Tuple

# Suspicious instruction patterns commonly employed in log injection attacks
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)?\s*", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"disregard\s+(above|all|previous)", re.IGNORECASE),
    re.compile(r"<\|(system|user|assistant|im_start|im_end)\|>", re.IGNORECASE),
    re.compile(r"\[(INST|/INST|SYS|/SYS)\]", re.IGNORECASE),
    re.compile(r"!\[.*?\]\((https?://.*?)\)", re.IGNORECASE),  # Markdown image exfiltration
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
]


class PromptInjectionSanitizer:
    """Sanitizes untrusted security logs and user inputs before LLM context injection."""

    def sanitize_untrusted_text(self, text: str) -> Tuple[str, List[str]]:
        """Scan and defang prompt injection signatures, returning sanitized text and warnings."""
        if not text:
            return "", []

        warnings: List[str] = []
        cleaned = text

        for pattern in INJECTION_PATTERNS:
            matches = pattern.findall(cleaned)
            if matches:
                warning_desc = f"Detected and defanged prompt injection pattern matching: '{pattern.pattern}'"
                warnings.append(warning_desc)
                cleaned = pattern.sub("[DEFANGED_INJECTION_ATTEMPT]", cleaned)

        # Remove control characters (except newline and tab)
        cleaned = "".join(ch for ch in cleaned if ch in "\n\t\r" or ord(ch) >= 32)
        return cleaned, warnings

    def wrap_evidence_block(self, log_id: str, raw_content: str) -> Tuple[str, List[str]]:
        """Wrap untrusted log content in an isolated, explicit XML data boundary."""
        sanitized_content, warnings = self.sanitize_untrusted_text(raw_content)

        # Strictly demarcate that content is untrusted data, never instructions
        wrapped = (
            f'<untrusted_evidence_log id="{log_id}">\n'
            f"{sanitized_content}\n"
            f"</untrusted_evidence_log>"
        )
        return wrapped, warnings
