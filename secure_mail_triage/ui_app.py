"""Streamlit UI for Secure Mail Triage.

Usage notes:
- UI-first flow supports Gmail ingestion and manual input.
- Uses a fixed model and requires OPENAI_API_KEY in the environment.
- Attachments are not analyzed.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

if __package__ is None:  # Allow running via `streamlit run secure_mail_triage/ui_app.py`.
    repo_root = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(repo_root)

from secure_mail_triage.agents import Email
from secure_mail_triage.gmail_client import (
    fetch_message_raw,
    get_gmail_service,
    list_message_ids,
    parse_gmail_message,
)
from secure_mail_triage.pipeline import create_llm_pipeline
from secure_mail_triage.storage import fetch_recent_results, save_result

FIXED_MODEL = "gpt-4o-mini"  # Single model used by the UI.
CATEGORY_QUERY_MAP = {
    "All": "",
    "Primary": "category:primary",
    "Promotions": "category:promotions",
    "Social": "category:social",
    "Updates": "category:updates",
}


def _build_pipeline():
    # Central place to set model defaults for the UI.
    return create_llm_pipeline(model=FIXED_MODEL)


def _render_result(result):
    st.subheader("Classification")
    st.json(
        {
            "verdict": result.features.get("verdict"),
            "risk_score": result.features.get("risk_score"),
            "rationale": result.features.get("rationale", []),
            "warnings": result.warnings,
        }
    )


def _message_label(item):
    subject = item["email"].subject or "(no subject)"
    sender = item["email"].sender or "(unknown sender)"
    received_at = item.get("received_at") or ""
    return f"{subject} | {sender} | {received_at}"


def _build_gmail_query(category: str, query: str) -> str:
    category_filter = CATEGORY_QUERY_MAP.get(category, "")
    parts = []
    if category_filter:
        parts.append(category_filter)
    if query:
        parts.append(query.strip())
    return " ".join(parts).strip()


def _load_gmail_messages(credentials_path, token_path, query, max_results):
    # Fetch raw Gmail messages and convert them into Email objects.
    service = get_gmail_service(credentials_path, token_path)
    messages = list_message_ids(service, query=query, max_results=max_results)
    items = []
    for message in messages:
        raw_bytes, meta = fetch_message_raw(service, message["id"])
        email, received_at = parse_gmail_message(raw_bytes)
        items.append(
            {
                "message_id": meta.get("message_id"),
                "thread_id": meta.get("thread_id"),
                "received_at": received_at,
                "email": email,
            }
        )
    return items


def main() -> None:
    st.set_page_config(page_title="Secure Mail Triage", page_icon=":shield:")
    st.title("Secure Mail Triage")

    # Streamlit session state holds the loaded Gmail cache and recent results.
    if "gmail_messages" not in st.session_state:
        st.session_state.gmail_messages = []
    if "gmail_results" not in st.session_state:
        st.session_state.gmail_results = []

    with st.sidebar:
        st.header("Settings")
        st.text_input("OpenAI model", value=FIXED_MODEL, disabled=True)
        if not os.getenv("OPENAI_API_KEY"):
            st.warning("OPENAI_API_KEY is not set in the environment.")
        db_path = st.text_input("SQLite DB path", value="triage.db")
        store_results = st.checkbox("Store results in DB", value=True)

    gmail_tab, manual_tab, results_tab = st.tabs(["Gmail", "Manual Input", "Recent Results"])

    with gmail_tab:
        st.subheader("Gmail Inbox")
        st.caption("Attachments are not analyzed; only email headers/body are classified.")

        with st.expander("Gmail settings", expanded=True):
            credentials_path = st.text_input("Credentials path", value="credentials.json")
            token_path = st.text_input("Token path", value="token.json")
            category = st.selectbox("Gmail category", options=list(CATEGORY_QUERY_MAP.keys()))
            query = st.text_input("Additional Gmail query", value="newer_than:7d")
            effective_query = _build_gmail_query(category, query)
            st.caption(f"Effective query: {effective_query or '(all mail)'}")
            max_results = st.number_input("Max results", min_value=1, max_value=50, value=5, step=1)
            if st.button("Load Gmail messages"):
                try:
                    st.session_state.gmail_messages = _load_gmail_messages(
                        credentials_path, token_path, effective_query, int(max_results)
                    )
                    st.session_state.gmail_results = []
                    st.success(f"Loaded {len(st.session_state.gmail_messages)} messages.")
                except Exception as exc:
                    st.error(f"Gmail load failed: {exc}")

        messages = st.session_state.gmail_messages
        if messages:
            label_map = {item["message_id"]: _message_label(item) for item in messages}
            options = list(label_map.keys())
            select_all = st.checkbox("Select all")
            selected_ids = st.multiselect(
                "Select emails to classify",
                options,
                default=options if select_all else [],
                format_func=lambda mid: label_map.get(mid, mid),
            )
            if st.button("Classify selected"):
                try:
                    if not os.getenv("OPENAI_API_KEY"):
                        raise ValueError("OPENAI_API_KEY is not set. Set it in your environment.")
                    pipeline = _build_pipeline()
                    results = []
                    for item in messages:
                        if item["message_id"] not in selected_ids:
                            continue
                        email = item["email"]
                        classification, details = pipeline.run_with_details(email)
                        results.append({"item": item, "classification": classification})
                        if store_results:
                            save_result(
                                db_path=db_path,
                                source="gmail_ui",
                                message_id=item.get("message_id"),
                                thread_id=item.get("thread_id"),
                                email=email,
                                classification=classification,
                                details=details,
                                received_at=item.get("received_at"),
                            )
                    st.session_state.gmail_results = results
                except Exception as exc:
                    st.error(f"Classification failed: {exc}")

            if st.session_state.gmail_results:
                for result in st.session_state.gmail_results:
                    label = _message_label(result["item"])
                    with st.expander(label):
                        _render_result(result["classification"])
        else:
            st.info("No Gmail messages loaded yet.")

    with manual_tab:
        st.subheader("Manual Email Entry")
        subject = st.text_input("Subject")
        sender = st.text_input("Sender")
        recipients_input = st.text_input("Recipients (comma-separated)")
        body = st.text_area("Body", height=200)

        if st.button("Classify manual email"):
            recipients = [r.strip() for r in recipients_input.split(",") if r.strip()]
            email = Email(subject=subject, body=body, sender=sender, recipients=recipients)
            try:
                if not os.getenv("OPENAI_API_KEY"):
                    raise ValueError("OPENAI_API_KEY is not set. Set it in your environment.")
                pipeline = _build_pipeline()
                classification, details = pipeline.run_with_details(email)
                _render_result(classification)
                if store_results:
                    save_result(
                        db_path=db_path,
                        source="ui",
                        message_id=None,
                        thread_id=None,
                        email=email,
                        classification=classification,
                        details=details,
                    )
            except Exception as exc:
                st.error(f"Classification failed: {exc}")

    with results_tab:
        st.subheader("Recent Results")
        if st.button("Refresh"):
            results = fetch_recent_results(db_path, limit=25)
            if results:
                st.dataframe(results, use_container_width=True)
            else:
                st.info("No results found.")


if __name__ == "__main__":
    main()
