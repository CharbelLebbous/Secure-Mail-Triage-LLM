"""Core agents for the secure mail triage classification workflow."""  # Module docstring summarizing the agents collection.

from __future__ import annotations  # Future import to support postponed evaluation of annotations.

import logging  # Standard logging library for debug and observability statements.
import re  # Regular expressions for URL and email pattern matching.
from dataclasses import dataclass, field  # Dataclass utilities for lightweight data containers.
from typing import Dict, Iterable, List, Optional, Sequence  # Typing helpers for clarity.
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
    attachments: List[Dict[str, str]] = field(default_factory=list)  # Attachment metadata list.


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
class EmailStructureAgent:  # Agent responsible for normalization and structural extraction.
    """Parses headers, links, and attachments with guardrails."""  # Docstring describing responsibilities.

    def __init__(self, max_body_length: int = 20000, max_attachments: int = 10):  # Configure limits for safety.
        self.max_body_length = max_body_length  # Maximum characters allowed from the email body.
        self.max_attachments = max_attachments  # Maximum number of attachments to process.

    def run(self, email: Email) -> AgentResult:  # Execute structural extraction for a single email.
        warnings: List[str] = []  # Collect warnings generated during processing.

        body = email.body or ""  # Safely handle missing body content.
        if len(body) > self.max_body_length:  # Enforce the body length guardrail.
            warnings.append("Body truncated due to size limit")  # Note that truncation occurred.
            body = body[: self.max_body_length]  # Truncate the body to the configured maximum.

        attachments = email.attachments[: self.max_attachments]  # Respect attachment count guardrail.
        if len(email.attachments) > self.max_attachments:  # If attachments were trimmed...
            warnings.append("Attachments truncated due to limit")  # ...record a warning.

        urls = extract_urls(body)  # Pull URLs out of the (possibly truncated) body.
        domains = extract_domains(urls)  # Derive domains from those URLs for downstream checks.

        features = {  # Bundle normalized structural attributes.
            "normalized_subject": (email.subject or "").strip(),  # Cleaned subject text.
            "normalized_body": body.strip(),  # Cleaned body text.
            "sender": email.sender.lower().strip(),  # Normalized sender address.
            "recipient_count": len(email.recipients),  # Count of recipients for anomaly detection.
            "urls": urls,  # List of extracted URLs.
            "domains": domains,  # Corresponding list of domains.
            "attachments": attachments,  # Trimmed attachment metadata.
        }

        logger.debug("EmailStructureAgent features: %s", features)  # Emit debug details for observability.
        return AgentResult(name="email_structure", features=features, warnings=warnings)  # Return structured result.


class ToneIntentAgent:  # Agent that scores urgency, coercion, and impersonation cues.
    """Scores urgency, coercion, and impersonation cues in text."""  # Docstring summarizing purpose.

    URGENCY_TERMS = [  # Terms indicating urgency.
        "urgent",
        "immediately",
        "asap",
        "now",
        "suspend",
        "suspension",
        "within 24 hours",
    ]
    COERCION_TERMS = [  # Terms indicating coercive language.
        "consequence",
        "penalty",
        "legal action",
        "final warning",
    ]
    IMPERSONATION_TERMS = ["ceo", "cfo", "admin", "it support", "helpdesk"]  # Roles often impersonated.

    def run(self, text: str) -> AgentResult:  # Evaluate tone cues within a text string.
        lowered = text.lower()  # Normalize text to lowercase for simple matching.

        def count_terms(terms: Sequence[str]) -> int:  # Inner helper to count term occurrences.
            return sum(lowered.count(term) for term in terms)  # Sum matches for each term.

        urgency_hits = count_terms(self.URGENCY_TERMS)  # Count urgency phrases present.
        coercion_hits = count_terms(self.COERCION_TERMS)  # Count coercive phrases present.
        impersonation_hits = count_terms(self.IMPERSONATION_TERMS)  # Count impersonation cues present.

        urgency_score = min(urgency_hits, 3)  # Cap urgency contribution to prevent runaway scoring.
        coercion_score = min(coercion_hits, 2)  # Cap coercion contribution.
        impersonation_score = min(impersonation_hits, 2)  # Cap impersonation contribution.

        features = {  # Package tone-related scores.
            "urgency_score": urgency_score,
            "coercion_score": coercion_score,
            "impersonation_score": impersonation_score,
        }
        logger.debug("ToneIntentAgent features: %s", features)  # Debug output for visibility.
        return AgentResult(name="tone_intent", features=features)  # Return structured tone result.


class ContentPolicyAgent:  # Agent detecting policy-violating requests.
    """Detects sensitive data requests or policy-violating asks."""  # Docstring explaining responsibilities.

    CREDENTIAL_TERMS = ["password", "passcode", "otp", "verification code", "login"]  # Credential-related terms.
    PAYMENT_TERMS = ["wire", "transfer", "invoice", "payment", "bank"]  # Payment-related terms.
    PII_TERMS = ["ssn", "social security", "date of birth", "dob", "address"]  # PII-related terms.

    def run(self, text: str) -> AgentResult:  # Evaluate text for policy violations.
        lowered = text.lower()  # Normalize casing for substring checks.

        def flag_terms(terms: Sequence[str]) -> List[str]:  # Inner helper returning matched terms.
            return [term for term in terms if term in lowered]  # Collect terms appearing in the text.

        credential_flags = flag_terms(self.CREDENTIAL_TERMS)  # Identify credential harvest signals.
        payment_flags = flag_terms(self.PAYMENT_TERMS)  # Identify payment request signals.
        pii_flags = flag_terms(self.PII_TERMS)  # Identify PII request signals.

        features = {  # Aggregate detection flags and spans.
            "credential_request": bool(credential_flags),  # Whether credential terms were seen.
            "payment_request": bool(payment_flags),  # Whether payment terms were seen.
            "pii_request": bool(pii_flags),  # Whether PII terms were seen.
            "spans": {  # Include matched terms for traceability.
                "credential_terms": credential_flags,
                "payment_terms": payment_flags,
                "pii_terms": pii_flags,
            },
        }
        logger.debug("ContentPolicyAgent features: %s", features)  # Debug output of matches.
        return AgentResult(name="content_policy", features=features)  # Return structured policy result.


class LinkAttachmentSafetyAgent:  # Agent assessing URLs and attachments for risk.
    """Evaluates URLs and attachments for obvious red flags."""  # Docstring describing safety checks.

    SUSPICIOUS_TLDS = {"ru", "cn", "tk", "zip", "xyz"}  # High-risk top-level domains.
    RISKY_EXTENSIONS = {"exe", "js", "vbs", "scr", "bat", "cmd", "jar", "ps1"}  # Dangerous file extensions.

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

    def _attachment_risk(self, attachment: Dict[str, str]) -> int:  # Private helper scoring attachments.
        name = attachment.get("name", "").lower()  # Extract attachment name safely.
        ext = name.rsplit(".", 1)[-1] if "." in name else ""  # Pull file extension if present.
        if ext in self.RISKY_EXTENSIONS:  # If the extension is dangerous...
            return 3  # ...assign high risk.
        if attachment.get("encrypted"):  # Treat encrypted attachments cautiously.
            return 2  # Medium risk for encrypted files.
        return 0  # Default neutral risk when no signals found.

    def run(self, domains: Iterable[str], attachments: Iterable[Dict[str, str]]) -> AgentResult:  # Evaluate URLs and attachments.
        domain_scores = {domain: self._domain_risk(domain) for domain in domains}  # Score each domain.
        attachment_scores = []  # Prepare a list to hold attachment risk entries.
        warnings: List[str] = []  # Collect warnings for encrypted attachments.

        for att in attachments:  # Iterate through each attachment.
            risk = self._attachment_risk(att)  # Score the attachment.
            attachment_scores.append({"name": att.get("name", ""), "risk": risk})  # Record name and risk.
            if att.get("encrypted"):  # If the attachment is encrypted...
                warnings.append(f"Encrypted attachment: {att.get('name', '')}")  # ...add a warning.

        features = {  # Bundle safety-related features.
            "domain_scores": domain_scores,
            "attachment_scores": attachment_scores,
        }
        logger.debug("LinkAttachmentSafetyAgent features: %s", features)  # Debug output for observability.
        return AgentResult(name="link_attachment_safety", features=features, warnings=warnings)  # Return results with warnings.


class UserOrgContextAgent:  # Agent applying organizational context and anomalies.
    """Applies allow/deny lists and simple anomaly checks."""  # Docstring describing contextual checks.

    def __init__(  # Initialize allow/block lists and domain allowances.
        self,
        allow_senders: Optional[Iterable[str]] = None,  # Optional sender allowlist.
        block_senders: Optional[Iterable[str]] = None,  # Optional sender blocklist.
        allow_domains: Optional[Iterable[str]] = None,  # Optional domain allowlist.
    ):
        self.allow_senders = {s.lower() for s in allow_senders or []}  # Normalize allowed senders.
        self.block_senders = {s.lower() for s in block_senders or []}  # Normalize blocked senders.
        self.allow_domains = {d.lower() for d in allow_domains or []}  # Normalize allowed domains.

    def run(self, sender: str, domains: Iterable[str], recipients: Iterable[str]) -> AgentResult:  # Evaluate context signals.
        sender_l = sender.lower()  # Normalize sender for comparisons.
        domains_l = [d.lower() for d in domains]  # Normalize domains list.
        recipients_l = [r.lower() for r in recipients]  # Normalize recipients list.

        warnings: List[str] = []  # Collect contextual warnings.
        risk_adjustment = 0  # Start with a neutral risk adjustment.

        if sender_l in self.block_senders:  # If sender is blocked...
            risk_adjustment += 3  # ...increase risk substantially.
            warnings.append("Sender on blocklist")  # Note the blocklist condition.
        if sender_l in self.allow_senders:  # If sender is explicitly allowed...
            risk_adjustment -= 2  # ...reduce risk.

        for domain in domains_l:  # Check each domain against the allowlist.
            if domain in self.allow_domains:  # If domain is allowed...
                risk_adjustment -= 1  # ...slightly reduce risk.
                break  # Break once one allowed domain is found to avoid over-adjusting.

        duplicate_recipient = len(recipients_l) != len(set(recipients_l)) and len(recipients_l) > 0  # Detect duplicate recipients.
        if duplicate_recipient:  # If duplicates exist...
            warnings.append("Duplicate recipients detected")  # ...record a warning.
            risk_adjustment += 1  # ...and modestly increase risk.

        features = {  # Package contextual findings.
            "risk_adjustment": risk_adjustment,
            "duplicate_recipient": duplicate_recipient,
        }
        logger.debug("UserOrgContextAgent features: %s", features)  # Debug output for traceability.
        return AgentResult(name="user_org_context", features=features, warnings=warnings)  # Return context assessment.


class ClassificationAggregator:  # Agent combining all signals into a final verdict.
    """Combines agent outputs into a final risk score and verdict."""  # Docstring explaining aggregation role.

    def __init__(self, phishing_threshold: int = 4):  # Configure the phishing threshold for verdicts.
        self.phishing_threshold = phishing_threshold  # Store the threshold for later comparisons.

    def run(  # Merge outputs from specialized agents.
        self,
        structure: AgentResult,
        tone: AgentResult,
        content: AgentResult,
        safety: AgentResult,
        context: AgentResult,
    ) -> AgentResult:
        score = 0  # Initialize cumulative risk score.
        rationale: List[str] = []  # Collect human-readable rationale statements.
        warnings: List[str] = []  # Aggregate warnings emitted by agents.

        # Tone
        tone_f = tone.features  # Short reference to tone features.
        score += tone_f.get("urgency_score", 0)  # Add urgency contribution.
        score += tone_f.get("coercion_score", 0)  # Add coercion contribution.
        score += tone_f.get("impersonation_score", 0)  # Add impersonation contribution.
        if tone_f.get("urgency_score"):  # If urgency detected...
            rationale.append("Urgent language detected")  # ...capture rationale message.
        if tone_f.get("coercion_score"):  # If coercion detected...
            rationale.append("Coercive language present")  # ...capture rationale message.
        if tone_f.get("impersonation_score"):  # If impersonation detected...
            rationale.append("Potential impersonation cues")  # ...capture rationale message.

        # Content policy
        content_f = content.features  # Short reference to content features.
        if content_f.get("credential_request"):  # Credential harvesting detected?
            score += 3  # Increase risk significantly.
            rationale.append("Requests credentials")  # Add rationale entry.
        if content_f.get("payment_request"):  # Payment request detected?
            score += 2  # Increase risk.
            rationale.append("Requests payment/transfer")  # Add rationale entry.
        if content_f.get("pii_request"):  # PII request detected?
            score += 2  # Increase risk.
            rationale.append("Asks for PII")  # Add rationale entry.

        # Safety
        safety_f = safety.features  # Short reference to safety features.
        domain_scores = safety_f.get("domain_scores", {})  # Pull domain risk scores.
        if domain_scores:  # If any domain scores exist...
            dom_score = sum(domain_scores.values())  # Sum domain contributions.
            score += dom_score  # Add to total score.
            if dom_score:  # If risk contributed...
                rationale.append("Risky domains detected")  # Add rationale entry.
        for att in safety_f.get("attachment_scores", []):  # Iterate over attachment risk entries.
            score += att.get("risk", 0)  # Add each attachment's risk.
            if att.get("risk", 0) >= 2:  # If attachment is medium/high risk...
                rationale.append(f"Risky attachment: {att.get('name', '')}")  # Add rationale entry.

        # Context
        context_f = context.features  # Short reference to context features.
        score += context_f.get("risk_adjustment", 0)  # Apply context-derived adjustment.
        if context_f.get("duplicate_recipient"):  # If duplicate recipients detected...
            rationale.append("Duplicate recipients anomaly")  # Add rationale entry.

        # Structure
        if structure.features.get("recipient_count", 0) == 0:  # If no recipients provided...
            score += 1  # Slightly increase risk due to missing metadata.
            rationale.append("No recipient list provided")  # Add rationale entry.

        warnings.extend(structure.warnings)  # Include structure warnings in final output.
        warnings.extend(safety.warnings)  # Include safety warnings in final output.
        warnings.extend(context.warnings)  # Include context warnings in final output.

        verdict = "phishing" if score >= self.phishing_threshold else "legitimate"  # Decide final verdict.
        features = {  # Package final classification features.
            "risk_score": score,
            "verdict": verdict,
            "rationale": rationale,
        }
        logger.debug("ClassificationAggregator features: %s", features)  # Debug output for final result.
        return AgentResult(name="classification", features=features, warnings=warnings)  # Return aggregated result.


__all__ = [  # Exported symbols from this module.
    "Email",  # Email data model.
    "AgentResult",  # Common result container.
    "EmailStructureAgent",  # Structural parsing agent.
    "ToneIntentAgent",  # Tone analysis agent.
    "ContentPolicyAgent",  # Content policy agent.
    "LinkAttachmentSafetyAgent",  # Link and attachment safety agent.
    "UserOrgContextAgent",  # Contextual anomaly agent.
    "ClassificationAggregator",  # Final aggregation agent.
]  # End of public exports list.
