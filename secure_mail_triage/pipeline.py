"""Classification pipeline wiring specialized agents together."""  # Module docstring summarizing purpose.
from __future__ import annotations  # Enable postponed evaluation of type annotations.

import logging  # Logging library for progress and debug messages.
from typing import Dict, Iterable, Optional  # Typing helpers for clarity of inputs.

from .agents import (  # Import agent classes and result model from local package.
    AgentResult,  # Type representing agent outputs.
    ClassificationAggregator,  # Aggregator that produces final verdicts.
    ContentPolicyAgent,  # Agent detecting policy-violating content.
    Email,  # Data model for emails.
    EmailStructureAgent,  # Agent handling structural extraction and guardrails.
    LinkAttachmentSafetyAgent,  # Agent scoring links and attachments.
    ToneIntentAgent,  # Agent assessing tone and intent signals.
    UserOrgContextAgent,  # Agent applying organizational context.
)

logger = logging.getLogger(__name__)  # Module-level logger for pipeline events.


class ClassificationPipeline:  # High-level orchestrator running all agents in sequence.
    """Runs the multi-agent classification workflow end-to-end."""  # Docstring describing pipeline role.

    def __init__(  # Initialize pipeline with optional configuration knobs.
        self,
        reputation: Optional[Dict[str, str]] = None,  # Optional domain reputation hints.
        allow_senders: Optional[Iterable[str]] = None,  # Optional sender allowlist.
        block_senders: Optional[Iterable[str]] = None,  # Optional sender blocklist.
        allow_domains: Optional[Iterable[str]] = None,  # Optional domain allowlist.
        phishing_threshold: int = 4,  # Threshold score at which verdict flips to phishing.
    ) -> None:
        self.structure_agent = EmailStructureAgent()  # Instantiate the structure extraction agent.
        self.tone_agent = ToneIntentAgent()  # Instantiate the tone and intent agent.
        self.content_agent = ContentPolicyAgent()  # Instantiate the content policy agent.
        self.safety_agent = LinkAttachmentSafetyAgent(reputation=reputation)  # Instantiate safety agent with reputation data.
        self.context_agent = UserOrgContextAgent(  # Instantiate context agent with allow/block configuration.
            allow_senders=allow_senders,
            block_senders=block_senders,
            allow_domains=allow_domains,
        )
        self.aggregator = ClassificationAggregator(phishing_threshold=phishing_threshold)  # Instantiate final aggregator.

    def run(self, email: Email) -> AgentResult:  # Execute the full classification flow for a single email.
        """Execute each agent and merge results into a classification."""  # Docstring summarizing run behavior.
        structure = self.structure_agent.run(email)  # Normalize and extract structural features.
        tone = self.tone_agent.run(structure.features["normalized_body"])  # Score tone cues using normalized body text.
        content = self.content_agent.run(structure.features["normalized_body"])  # Flag policy violations from same text.
        safety = self.safety_agent.run(  # Evaluate domains and attachments for risk.
            structure.features.get("domains", []), structure.features.get("attachments", [])
        )
        context = self.context_agent.run(  # Apply organizational context and anomalies.
            sender=structure.features.get("sender", ""),
            domains=structure.features.get("domains", []),
            recipients=email.recipients,
        )

        classification = self.aggregator.run(structure, tone, content, safety, context)  # Merge all agent outputs.

        logger.info(  # Log final verdict, score, and any warnings.
            "Classification complete: verdict=%s score=%s warnings=%s",
            classification.features["verdict"],
            classification.features["risk_score"],
            classification.warnings,
        )
        return classification  # Return the aggregated classification result to the caller.


__all__ = ["ClassificationPipeline"]  # Export the pipeline class for consumers.
