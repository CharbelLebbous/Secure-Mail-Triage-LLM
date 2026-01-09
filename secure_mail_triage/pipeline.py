"""Classification pipeline wiring specialized agents together.

Usage notes:
- create_llm_pipeline builds the LLM agentic workflow used by the CLI/UI.
"""  # Module docstring summarizing purpose.
from __future__ import annotations  # Enable postponed evaluation of type annotations.

from typing import Dict, Iterable, Optional  # Typing helpers for clarity of inputs.

def create_llm_pipeline(
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    reputation: Optional[Dict[str, str]] = None,
    allow_senders: Optional[Iterable[str]] = None,
    block_senders: Optional[Iterable[str]] = None,
    allow_domains: Optional[Iterable[str]] = None,
    phishing_threshold: int = 4,
):
    """Factory for LLM-backed pipeline to avoid importing OpenAI unless needed."""
    from .config import DEFAULT_ALLOW_DOMAINS, DEFAULT_ALLOW_SENDERS, DEFAULT_BLOCK_SENDERS
    from .llm_client import LLMClient
    from .llm_agents import LLMClassificationPipeline

    # Use environment defaults unless explicitly overridden by the caller.
    client = LLMClient(api_key=api_key, model=model)
    return LLMClassificationPipeline(
        client=client,
        reputation=reputation,
        allow_senders=DEFAULT_ALLOW_SENDERS if allow_senders is None else allow_senders,
        block_senders=DEFAULT_BLOCK_SENDERS if block_senders is None else block_senders,
        allow_domains=DEFAULT_ALLOW_DOMAINS if allow_domains is None else allow_domains,
        phishing_threshold=phishing_threshold,
    )


__all__ = ["create_llm_pipeline"]  # Exported symbols.
