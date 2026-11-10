"""Validator verifying that all AI citations strictly correspond to real evidence IDs."""

import re
from typing import List, Set, Tuple

CITATION_REGEX = re.compile(r"\[((?:evt|alt)_[a-zA-Z0-9_\-]+)\]")


class CitationValidator:
    """Verifies that every event and alert cited by the AI exists in the incident evidence."""

    def __init__(self, allowed_event_ids: Set[str], allowed_alert_ids: Set[str]):
        self.allowed_event_ids = allowed_event_ids
        self.allowed_alert_ids = allowed_alert_ids
        self.all_allowed = allowed_event_ids | allowed_alert_ids

    def extract_citations_from_text(self, text: str) -> List[str]:
        """Extract all [evt_...] and [alt_...] citation tokens from unstructured text."""
        return CITATION_REGEX.findall(text)

    def validate_citations(self, citations: List[str]) -> Tuple[bool, List[str], List[str]]:
        """Validate a list of citation strings against the authorized evidence set."""
        valid: List[str] = []
        invalid: List[str] = []

        for cit in citations:
            # Strip brackets if present
            clean_cit = cit.strip("[] \t")
            if clean_cit in self.all_allowed:
                if clean_cit not in valid:
                    valid.append(clean_cit)
            else:
                if clean_cit not in invalid:
                    invalid.append(clean_cit)

        is_valid = (len(invalid) == 0)
        return is_valid, valid, invalid
