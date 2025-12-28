"""Core agents for the secure mail triage classification workflow.

Each agent focuses on a single responsibility and returns a structured
payload that the final aggregator can consume. All heuristics are
lightweight and dependency-free to keep the pipeline reproducible.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------- Shared models -----------------------------
@dataclass
class Email:
    subject: str
    body: str
    sender: str = ""
    recipients: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class AgentResult:
    name: str
    features: Dict[str, object]
    warnings: List[str] = field(default_factory=list)


# --------------------------- Helper functions ---------------------------
URL_PATTERN = re.compile(r"https?://[^\s]+", flags=re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_urls(text: str) -> List[str]:
    return URL_PATTERN.findall(text)


def extract_domains(urls: Iterable[str]) -> List[str]:
    domains: List[str] = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc.lower())
    return domains


# ------------------------- Agent implementations ------------------------
class EmailStructureAgent:
    """Parses headers, links, and attachments with guardrails."""

    def __init__(self, max_body_length: int = 20000, max_attachments: int = 10):
        self.max_body_length = max_body_length
        self.max_attachments = max_attachments

    def run(self, email: Email) -> AgentResult:
        warnings: List[str] = []

        body = email.body or ""
        if len(body) > self.max_body_length:
            warnings.append("Body truncated due to size limit")
            body = body[: self.max_body_length]

        attachments = email.attachments[: self.max_attachments]
        if len(email.attachments) > self.max_attachments:
            warnings.append("Attachments truncated due to limit")

        urls = extract_urls(body)
        domains = extract_domains(urls)

        features = {
            "normalized_subject": (email.subject or "").strip(),
            "normalized_body": body.strip(),
            "sender": email.sender.lower().strip(),
            "recipient_count": len(email.recipients),
            "urls": urls,
            "domains": domains,
            "attachments": attachments,
        }

        logger.debug("EmailStructureAgent features: %s", features)
        return AgentResult(name="email_structure", features=features, warnings=warnings)


class ToneIntentAgent:
    """Scores urgency, coercion, and impersonation cues in text."""

    URGENCY_TERMS = [
        "urgent",
        "immediately",
        "asap",
        "now",
        "suspend",
        "suspension",
        "within 24 hours",
    ]
    COERCION_TERMS = [
        "consequence",
        "penalty",
        "legal action",
        "final warning",
    ]
    IMPERSONATION_TERMS = ["ceo", "cfo", "admin", "it support", "helpdesk"]

    def run(self, text: str) -> AgentResult:
        lowered = text.lower()

        def count_terms(terms: Sequence[str]) -> int:
            return sum(lowered.count(term) for term in terms)

        urgency_hits = count_terms(self.URGENCY_TERMS)
        coercion_hits = count_terms(self.COERCION_TERMS)
        impersonation_hits = count_terms(self.IMPERSONATION_TERMS)

        urgency_score = min(urgency_hits, 3)
        coercion_score = min(coercion_hits, 2)
        impersonation_score = min(impersonation_hits, 2)

        features = {
            "urgency_score": urgency_score,
            "coercion_score": coercion_score,
            "impersonation_score": impersonation_score,
        }
        logger.debug("ToneIntentAgent features: %s", features)
        return AgentResult(name="tone_intent", features=features)


class ContentPolicyAgent:
    """Detects sensitive data requests or policy-violating asks."""

    CREDENTIAL_TERMS = ["password", "passcode", "otp", "verification code", "login"]
    PAYMENT_TERMS = ["wire", "transfer", "invoice", "payment", "bank"]
    PII_TERMS = ["ssn", "social security", "date of birth", "dob", "address"]

    def run(self, text: str) -> AgentResult:
        lowered = text.lower()

        def flag_terms(terms: Sequence[str]) -> List[str]:
            return [term for term in terms if term in lowered]

        credential_flags = flag_terms(self.CREDENTIAL_TERMS)
        payment_flags = flag_terms(self.PAYMENT_TERMS)
        pii_flags = flag_terms(self.PII_TERMS)

        features = {
            "credential_request": bool(credential_flags),
            "payment_request": bool(payment_flags),
            "pii_request": bool(pii_flags),
            "spans": {
                "credential_terms": credential_flags,
                "payment_terms": payment_flags,
                "pii_terms": pii_flags,
            },
        }
        logger.debug("ContentPolicyAgent features: %s", features)
        return AgentResult(name="content_policy", features=features)


class LinkAttachmentSafetyAgent:
    """Evaluates URLs and attachments for obvious red flags."""

    SUSPICIOUS_TLDS = {"ru", "cn", "tk", "zip", "xyz"}
    RISKY_EXTENSIONS = {"exe", "js", "vbs", "scr", "bat", "cmd", "jar", "ps1"}

    def __init__(self, reputation: Optional[Dict[str, str]] = None):
        self.reputation = reputation or {}

    def _domain_risk(self, domain: str) -> int:
        parsed = domain.lower()
        if parsed in self.reputation and self.reputation[parsed] == "bad":
            return 3
        suffix = parsed.split(".")[-1]
        if suffix in self.SUSPICIOUS_TLDS:
            return 2
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed):
            return 2
        return 0

    def _attachment_risk(self, attachment: Dict[str, str]) -> int:
        name = attachment.get("name", "").lower()
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in self.RISKY_EXTENSIONS:
            return 3
        if attachment.get("encrypted"):
            return 2
        return 0

    def run(self, domains: Iterable[str], attachments: Iterable[Dict[str, str]]) -> AgentResult:
        domain_scores = {domain: self._domain_risk(domain) for domain in domains}
        attachment_scores = []
        warnings: List[str] = []

        for att in attachments:
            risk = self._attachment_risk(att)
            attachment_scores.append({"name": att.get("name", ""), "risk": risk})
            if att.get("encrypted"):
                warnings.append(f"Encrypted attachment: {att.get('name', '')}")

        features = {
            "domain_scores": domain_scores,
            "attachment_scores": attachment_scores,
        }
        logger.debug("LinkAttachmentSafetyAgent features: %s", features)
        return AgentResult(name="link_attachment_safety", features=features, warnings=warnings)


class UserOrgContextAgent:
    """Applies allow/deny lists and simple anomaly checks."""

    def __init__(
        self,
        allow_senders: Optional[Iterable[str]] = None,
        block_senders: Optional[Iterable[str]] = None,
        allow_domains: Optional[Iterable[str]] = None,
    ):
        self.allow_senders = {s.lower() for s in allow_senders or []}
        self.block_senders = {s.lower() for s in block_senders or []}
        self.allow_domains = {d.lower() for d in allow_domains or []}

    def run(self, sender: str, domains: Iterable[str], recipients: Iterable[str]) -> AgentResult:
        sender_l = sender.lower()
        domains_l = [d.lower() for d in domains]
        recipients_l = [r.lower() for r in recipients]

        warnings: List[str] = []
        risk_adjustment = 0

        if sender_l in self.block_senders:
            risk_adjustment += 3
            warnings.append("Sender on blocklist")
        if sender_l in self.allow_senders:
            risk_adjustment -= 2

        for domain in domains_l:
            if domain in self.allow_domains:
                risk_adjustment -= 1
                break

        duplicate_recipient = len(recipients_l) != len(set(recipients_l)) and len(recipients_l) > 0
        if duplicate_recipient:
            warnings.append("Duplicate recipients detected")
            risk_adjustment += 1

        features = {
            "risk_adjustment": risk_adjustment,
            "duplicate_recipient": duplicate_recipient,
        }
        logger.debug("UserOrgContextAgent features: %s", features)
        return AgentResult(name="user_org_context", features=features, warnings=warnings)


class ClassificationAggregator:
    """Combines agent outputs into a final risk score and verdict."""

    def __init__(self, phishing_threshold: int = 4):
        self.phishing_threshold = phishing_threshold

    def run(
        self,
        structure: AgentResult,
        tone: AgentResult,
        content: AgentResult,
        safety: AgentResult,
        context: AgentResult,
    ) -> AgentResult:
        score = 0
        rationale: List[str] = []
        warnings: List[str] = []

        # Tone
        tone_f = tone.features
        score += tone_f.get("urgency_score", 0)
        score += tone_f.get("coercion_score", 0)
        score += tone_f.get("impersonation_score", 0)
        if tone_f.get("urgency_score"):
            rationale.append("Urgent language detected")
        if tone_f.get("coercion_score"):
            rationale.append("Coercive language present")
        if tone_f.get("impersonation_score"):
            rationale.append("Potential impersonation cues")

        # Content policy
        content_f = content.features
        if content_f.get("credential_request"):
            score += 3
            rationale.append("Requests credentials")
        if content_f.get("payment_request"):
            score += 2
            rationale.append("Requests payment/transfer")
        if content_f.get("pii_request"):
            score += 2
            rationale.append("Asks for PII")

        # Safety
        safety_f = safety.features
        domain_scores = safety_f.get("domain_scores", {})
        if domain_scores:
            dom_score = sum(domain_scores.values())
            score += dom_score
            if dom_score:
                rationale.append("Risky domains detected")
        for att in safety_f.get("attachment_scores", []):
            score += att.get("risk", 0)
            if att.get("risk", 0) >= 2:
                rationale.append(f"Risky attachment: {att.get('name', '')}")

        # Context
        context_f = context.features
        score += context_f.get("risk_adjustment", 0)
        if context_f.get("duplicate_recipient"):
            rationale.append("Duplicate recipients anomaly")

        # Structure
        if structure.features.get("recipient_count", 0) == 0:
            score += 1
            rationale.append("No recipient list provided")

        warnings.extend(structure.warnings)
        warnings.extend(safety.warnings)
        warnings.extend(context.warnings)

        verdict = "phishing" if score >= self.phishing_threshold else "legitimate"
        features = {
            "risk_score": score,
            "verdict": verdict,
            "rationale": rationale,
        }
        logger.debug("ClassificationAggregator features: %s", features)
        return AgentResult(name="classification", features=features, warnings=warnings)


__all__ = [
    "Email",
    "AgentResult",
    "EmailStructureAgent",
    "ToneIntentAgent",
    "ContentPolicyAgent",
    "LinkAttachmentSafetyAgent",
    "UserOrgContextAgent",
    "ClassificationAggregator",
]
