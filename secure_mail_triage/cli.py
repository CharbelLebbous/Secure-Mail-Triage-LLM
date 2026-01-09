"""Command-line interface for Secure Mail Triage.

Usage notes:
- CLI is LLM-only.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Optional

from .agents import Email
from .pipeline import create_llm_pipeline
from .storage import save_result


def _build_pipeline(model: Optional[str] = None):
    # LLM-only CLI entry; adjust create_llm_pipeline if you want a different model.
    return create_llm_pipeline(model=model)


def _print_result(subject: str, classification, warnings):
    print(f"=== {subject} ===")
    print(
        json.dumps(
            {
                "verdict": classification.features.get("verdict"),
                "risk_score": classification.features.get("risk_score"),
                "rationale": classification.features.get("rationale", []),
            },
            indent=2,
        )
    )
    if warnings:
        print(f"Warnings: {warnings}")
    print("")


def _handle_text(args) -> None:
    pipeline = _build_pipeline(model=args.model)
    email = Email(
        subject=args.subject,
        body=args.body,
        sender=args.sender,
        recipients=args.recipients or [],
    )
    classification, details = pipeline.run_with_details(email)
    _print_result(email.subject, classification, classification.warnings)
    if not args.no_store and args.db:
        save_result(
            db_path=args.db,
            source="text",
            message_id=None,
            thread_id=None,
            email=email,
            classification=classification,
            details=details,
        )


def _handle_gmail(args) -> None:
    from .gmail_client import fetch_message_raw, get_gmail_service, list_message_ids, parse_gmail_message

    pipeline = _build_pipeline(model=args.model)
    service = get_gmail_service(args.credentials, args.token)
    messages = list_message_ids(service, query=args.query, max_results=args.max_results)
    for message in messages:
        raw_bytes, meta = fetch_message_raw(service, message["id"])
        email, received_at = parse_gmail_message(raw_bytes)
        classification, details = pipeline.run_with_details(email)
        _print_result(email.subject or "(no subject)", classification, classification.warnings)
        internal_date = meta.get("internal_date")
        if internal_date and not received_at:
            try:
                received_at = datetime.fromtimestamp(int(internal_date) / 1000, tz=timezone.utc).isoformat()
            except (TypeError, ValueError):
                received_at = None
        if not args.no_store and args.db:
            save_result(
                db_path=args.db,
                source="gmail",
                message_id=meta.get("message_id"),
                thread_id=meta.get("thread_id"),
                email=email,
                classification=classification,
                details=details,
                received_at=received_at,
            )


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Secure Mail Triage CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gmail_parser = subparsers.add_parser("gmail", help="Fetch and classify Gmail messages")
    gmail_parser.add_argument("--credentials", default="credentials.json", help="Path to Gmail OAuth credentials")
    gmail_parser.add_argument("--token", default="token.json", help="Path to store Gmail OAuth token")
    gmail_parser.add_argument("--query", default="newer_than:7d", help="Gmail search query")
    gmail_parser.add_argument("--max-results", type=int, default=5, help="Max messages to fetch")
    gmail_parser.add_argument("--model", default=None, help="OpenAI model override")
    gmail_parser.add_argument("--db", default="triage.db", help="SQLite DB path for persistence")
    gmail_parser.add_argument("--no-store", action="store_true", help="Skip storing results")
    gmail_parser.set_defaults(func=_handle_gmail)

    text_parser = subparsers.add_parser("text", help="Classify a single email from text")
    text_parser.add_argument("--subject", required=True, help="Email subject")
    text_parser.add_argument("--body", required=True, help="Email body")
    text_parser.add_argument("--sender", default="", help="Sender email")
    text_parser.add_argument("--recipients", nargs="*", default=[], help="Recipients")
    text_parser.add_argument("--model", default=None, help="OpenAI model override")
    text_parser.add_argument("--db", default="triage.db", help="SQLite DB path for persistence")
    text_parser.add_argument("--no-store", action="store_true", help="Skip storing results")
    text_parser.set_defaults(func=_handle_text)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
