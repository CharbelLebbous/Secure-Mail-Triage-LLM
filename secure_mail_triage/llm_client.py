"""OpenAI client wrapper for structured JSON responses.

Usage notes:
- Reads OPENAI_API_KEY (and optional OPENAI_MODEL) from the environment.
- Enforces JSON mode to reduce noisy output and parsing warnings.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from openai import OpenAI

DEFAULT_MODEL = "gpt-4o-mini"
WRAPPED_JSON_WARNING = "wrapped JSON extracted"


@dataclass
class LLMResult:
    """Parsed LLM response with raw text and parse status."""

    data: Dict[str, Any]
    raw_text: str
    parse_error: Optional[str] = None


def _extract_json_object(text: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    stripped = text.strip()
    if not stripped:
        return None, "empty response"
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed, None
        return None, "response is not a JSON object"
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None, "no JSON object found"
        snippet = stripped[start : end + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed, WRAPPED_JSON_WARNING
            return None, "extracted JSON is not an object"
        except json.JSONDecodeError as exc:
            return None, f"JSON decode error: {exc}"


class LLMClient:
    """Thin wrapper around OpenAI chat completions with JSON parsing."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.2,
        use_json_mode: bool = True,
    ) -> None:
        resolved_key = api_key or os.getenv("OPENAI_API_KEY")
        if not resolved_key:
            raise ValueError("OPENAI_API_KEY is not set")
        self.client = OpenAI(api_key=resolved_key)
        self.model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
        self.temperature = temperature
        self.use_json_mode = use_json_mode

    def run_json(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 500,
        temperature: Optional[float] = None,
    ) -> LLMResult:
        request_kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": max_tokens,
        }
        if self.use_json_mode:
            request_kwargs["response_format"] = {"type": "json_object"}
        try:
            response = self.client.chat.completions.create(**request_kwargs)
        except Exception:
            if "response_format" in request_kwargs:
                request_kwargs.pop("response_format", None)
                response = self.client.chat.completions.create(**request_kwargs)
            else:
                raise
        text = response.choices[0].message.content or ""
        data, error = _extract_json_object(text)
        return LLMResult(data=data or {}, raw_text=text, parse_error=error)
