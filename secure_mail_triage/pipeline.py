"""Classification pipeline wiring specialized agents together."""
from __future__ import annotations

import logging
from typing import Dict, Iterable, Optional

from .agents import (
    AgentResult,
    ClassificationAggregator,
    ContentPolicyAgent,
    Email,
    EmailStructureAgent,
    LinkAttachmentSafetyAgent,
    ToneIntentAgent,
    UserOrgContextAgent,
)

logger = logging.getLogger(__name__)


class ClassificationPipeline:
    """Runs the multi-agent classification workflow end-to-end."""

    def __init__(
        self,
        reputation: Optional[Dict[str, str]] = None,
        allow_senders: Optional[Iterable[str]] = None,
        block_senders: Optional[Iterable[str]] = None,
        allow_domains: Optional[Iterable[str]] = None,
        phishing_threshold: int = 4,
    ) -> None:
        self.structure_agent = EmailStructureAgent()
        self.tone_agent = ToneIntentAgent()
        self.content_agent = ContentPolicyAgent()
        self.safety_agent = LinkAttachmentSafetyAgent(reputation=reputation)
        self.context_agent = UserOrgContextAgent(
            allow_senders=allow_senders,
            block_senders=block_senders,
            allow_domains=allow_domains,
        )
        self.aggregator = ClassificationAggregator(phishing_threshold=phishing_threshold)

    def run(self, email: Email) -> AgentResult:
        """Execute each agent and merge results into a classification."""
        structure = self.structure_agent.run(email)
        tone = self.tone_agent.run(structure.features["normalized_body"])
        content = self.content_agent.run(structure.features["normalized_body"])
        safety = self.safety_agent.run(
            structure.features.get("domains", []), structure.features.get("attachments", [])
        )
        context = self.context_agent.run(
            sender=structure.features.get("sender", ""),
            domains=structure.features.get("domains", []),
            recipients=email.recipients,
        )

        classification = self.aggregator.run(structure, tone, content, safety, context)

        logger.info(
            "Classification complete: verdict=%s score=%s warnings=%s",
            classification.features["verdict"],
            classification.features["risk_score"],
            classification.warnings,
        )
        return classification


__all__ = ["ClassificationPipeline"]
