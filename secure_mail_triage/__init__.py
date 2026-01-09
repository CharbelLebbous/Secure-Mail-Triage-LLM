"""Secure Mail Triage agents and pipeline components."""  # Package docstring summarizing contents.

from .agents import AgentResult, Email
from .pipeline import create_llm_pipeline

__all__ = ["AgentResult", "Email", "create_llm_pipeline"]
