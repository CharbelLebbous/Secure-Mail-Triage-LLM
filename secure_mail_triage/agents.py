"""Core models and deterministic helpers for the secure mail triage workflow.

Usage notes:
- Email and AgentResult are shared across all pipelines.
- EmailStructureExtractor is deterministic preprocessing used by all pipelines.
- LinkSafetyAgent provides rule-based domain checks used by the LLM pipeline.
- Attachments are not analyzed; only minimal counts may be retained.
"""  # Module docstring summarizing the agents collection.

from __future__ import annotations  # Future import to support postponed evaluation of annotations.

import logging  # Standard logging library for debug and observability statements.
import re  # Regular expressions for URL and email pattern matching.
from dataclasses import dataclass, field  # Dataclass utilities for lightweight data containers.
from typing import Dict, Iterable, List, Optional  # Typing helpers for clarity.
from urllib.parse import urlparse  # URL parsing helper to extract domain parts.

logger = logging.getLogger(__name__)  # Module-level logger used by all agents.

# ---------------------------- Shared models -----------------------------  # Section header indicating shared data models.
@dataclass  # Decorator to auto-generate init and repr methods.
class Email:  # Model for incoming email data used across agents.
    subject: str  # Subject line of the email.
    body: str  # Body content of the email.
    sender: str = ""  # Optional sender address; defaults to empty if missing.
    recipients: List[str] = field(default_factory=list)  # Recipient list with a safe default.
    headers: Dict[str, str] = field(default_factory=dict)  # Optional headers dictionary.
    attachments: List[Dict[str, str]] = field(default_factory=list)  # Attachment metadata list (ignored by pipeline).
    attachment_count: int = 0  # Optional count to note attachments without inspecting contents.


@dataclass  # Decorator to generate boilerplate methods for agent outputs.
class AgentResult:  # Container for each agent's output features and warnings.
    name: str  # Identifier for the agent producing the result.
    features: Dict[str, object]  # Structured payload describing extracted signals.
    warnings: List[str] = field(default_factory=list)  # Any guardrail or informational warnings.


# --------------------------- Helper functions ---------------------------  # Section header for shared utility functions.
URL_PATTERN = re.compile(r"https?://[^\s]+", flags=re.IGNORECASE)  # Regex to locate HTTP/HTTPS URLs.
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")  # Regex to match email addresses.


def extract_urls(text: str) -> List[str]:  # Helper to extract URLs from arbitrary text.
    return URL_PATTERN.findall(text)  # Return all regex matches as a list.


def extract_domains(urls: Iterable[str]) -> List[str]:  # Helper to pull domains from a list of URLs.
    domains: List[str] = []  # Start with an empty collection of domains.
    for url in urls:  # Iterate over each URL string.
        parsed = urlparse(url)  # Parse the URL into components.
        if parsed.netloc:  # Only keep entries that include a network location (domain or host).
            domains.append(parsed.netloc.lower())  # Store the lowercase domain for normalization.
    return domains  # Provide the collected domains back to the caller.


# ------------------------- Agent implementations ------------------------  # Section header for agent classes.
class EmailStructureExtractor:  # Deterministic preprocessing for normalization and extraction.
    """Parses headers and links with guardrails (no attachment analysis)."""  # Docstring describing responsibilities.

    def __init__(self, max_body_length: int = 20000):  # Configure limits for safety.
        self.max_body_length = max_body_length  # Maximum characters allowed from the email body.

    def run(self, email: Email) -> AgentResult:  # Execute structural extraction for a single email.
        warnings: List[str] = []  # Collect warnings generated during processing.

        body = email.body or ""  # Safely handle missing body content.
        if len(body) > self.max_body_length:  # Enforce the body length guardrail.
            warnings.append("Body truncated due to size limit")  # Note that truncation occurred.
            body = body[: self.max_body_length]  # Truncate the body to the configured maximum.

        attachment_count = email.attachment_count or len(email.attachments)
        if attachment_count:
            warnings.append("Attachments present but not analyzed")

        urls = extract_urls(body)  # Pull URLs out of the (possibly truncated) body.
        domains = extract_domains(urls)  # Derive domains from those URLs for downstream checks.

        features = {  # Bundle normalized structural attributes.
            "normalized_subject": (email.subject or "").strip(),  # Cleaned subject text.
            "normalized_body": body.strip(),  # Cleaned body text.
            "sender": email.sender.lower().strip(),  # Normalized sender address.
            "recipient_count": len(email.recipients),  # Count of recipients for anomaly detection.
            "urls": urls,  # List of extracted URLs.
            "domains": domains,  # Corresponding list of domains.
            "attachment_count": attachment_count,  # Count only; contents are not analyzed.
            "attachments_analyzed": False,  # Explicitly document the policy.
        }

        logger.debug("EmailStructureExtractor features: %s", features)  # Emit debug details for observability.
        return AgentResult(name="email_structure", features=features, warnings=warnings)  # Return structured result.

class LinkSafetyAgent:  # Agent assessing URLs for risk.
    """Evaluates URLs for obvious red flags (no attachment analysis)."""  # Docstring describing safety checks.

    SUSPICIOUS_TLDS = {"ru", "cn", "tk", "zip", "xyz"}  # High-risk top-level domains.

    def __init__(self, reputation: Optional[Dict[str, str]] = None):  # Optionally inject reputation hints.
        self.reputation = reputation or {}  # Store provided reputation map or default to empty.

    def _domain_risk(self, domain: str) -> int:  # Private helper to compute domain risk score.
        parsed = domain.lower()  # Normalize the domain for consistent comparison.
        if parsed in self.reputation and self.reputation[parsed] == "bad":  # Check explicit bad reputation.
            return 3  # Highest risk when domain is flagged as bad.
        suffix = parsed.split(".")[-1]  # Extract the top-level domain.
        if suffix in self.SUSPICIOUS_TLDS:  # Check if TLD is suspicious.
            return 2  # Medium risk for suspicious TLD.
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed):  # Treat raw IP addresses as suspicious.
            return 2  # Medium risk for numeric hosts.
        return 0  # Default to neutral risk otherwise.

    def run(self, domains: Iterable[str]) -> AgentResult:  # Evaluate URLs for risk.
        domain_scores = {domain: self._domain_risk(domain) for domain in domains}  # Score each domain.
        warnings: List[str] = []  # No attachment analysis warnings.
        features = {  # Bundle safety-related features.
            "domain_scores": domain_scores,
        }
        logger.debug("LinkSafetyAgent features: %s", features)  # Debug output for observability.
        return AgentResult(name="link_safety", features=features, warnings=warnings)  # Return results with warnings.


__all__ = [  # Exported symbols from this module.
    "Email",  # Email data model.
    "AgentResult",  # Common result container.
    "EmailStructureExtractor",  # Structural parsing agent.
    "LinkSafetyAgent",  # Link safety agent.
]  # End of public exports list.
