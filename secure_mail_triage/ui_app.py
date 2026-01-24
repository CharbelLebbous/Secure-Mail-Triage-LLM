"""Streamlit UI for Secure Mail Triage.

Usage notes:
- UI-first flow supports Gmail ingestion and manual input.
- Uses a fixed model and requires OPENAI_API_KEY in the environment.
- Attachments are not analyzed.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from email.utils import parseaddr
from typing import Optional

import streamlit as st
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

if __package__ is None:  # Allow running via `streamlit run secure_mail_triage/ui_app.py`.
    repo_root = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(repo_root)

from secure_mail_triage.agents import Email
from secure_mail_triage.gmail_client import (
    DEFAULT_SCOPES,
    build_gmail_service,
    fetch_message_raw,
    get_gmail_service,
    get_profile_email,
    list_message_page,
    parse_gmail_message,
)
from secure_mail_triage.pipeline import create_llm_pipeline
from secure_mail_triage.storage import fetch_recent_results, save_result

FIXED_MODEL = "gpt-4o-mini"  # Single model used by the UI.
CREDENTIALS_PATH = "credentials.json"
TOKEN_PATH = ".gmail_token.json"
DEFAULT_MAX_RESULTS = 10
CATEGORY_QUERY_MAP = {
    "All": "",
    "Primary": "category:primary",
    "Promotions": "category:promotions",
    "Social": "category:social",
    "Updates": "category:updates",
}
TIME_FILTERS = {
    "Any time": "",
    "Last 24 hours": "newer_than:1d",
    "Last 7 days": "newer_than:7d",
    "Last 30 days": "newer_than:30d",
    "Last 90 days": "newer_than:90d",
}


def _build_pipeline(api_key: Optional[str] = None):
    # Central place to set model defaults for the UI.
    return create_llm_pipeline(model=FIXED_MODEL, api_key=api_key)


def _render_result(result):
    verdict = str(result.features.get("verdict", "")).lower()
    risk_score = int(result.features.get("risk_score", 0) or 0)
    confidence = result.features.get("confidence")
    rationale = result.features.get("rationale", [])
    warnings = result.warnings or []

    if verdict == "phishing":
        st.error("Phishing")
    else:
        st.success("Legitimate")

    cols = st.columns(3)
    cols[0].metric("Risk score", risk_score)
    cols[1].metric("Verdict", verdict.title() if verdict else "Unknown")
    if confidence is not None:
        cols[2].metric("Confidence", f"{float(confidence):.2f}")
    else:
        cols[2].metric("Warnings", len(warnings))

    st.progress(min(max(risk_score / 10, 0.0), 1.0))

    if rationale:
        st.subheader("Rationale")
        for item in rationale:
            st.write(f"- {item}")

    if warnings:
        st.warning("Warnings")
        for warning in warnings:
            st.write(f"- {warning}")


def _message_label(item):
    subject = item["email"].subject or "(no subject)"
    sender = item["email"].sender or "(unknown sender)"
    received_at = item.get("received_at") or ""
    return f"{subject} | {sender} | {received_at}"


def _group_results(results):
    phishing = []
    legitimate = []
    for result in results:
        verdict = str(result["classification"].features.get("verdict", "")).lower()
        if verdict == "phishing":
            phishing.append(result)
        else:
            legitimate.append(result)
    phishing.sort(
        key=lambda item: int(item["classification"].features.get("risk_score", 0) or 0),
        reverse=True,
    )
    legitimate.sort(
        key=lambda item: int(item["classification"].features.get("risk_score", 0) or 0),
        reverse=True,
    )
    return phishing, legitimate


def _render_recent_item(item):
    verdict = str(item.get("verdict", "")).lower()
    risk_score = int(item.get("risk_score", 0) or 0)
    subject = item.get("subject") or "(no subject)"
    sender = item.get("sender") or "(unknown sender)"
    received_at = item.get("received_at") or ""
    label = f"{subject} | {sender} | {received_at}"
    if verdict == "phishing":
        st.error(f"Phishing - {label}")
    else:
        st.success(f"Legitimate - {label}")
    st.metric("Risk score", risk_score)
    rationale = item.get("rationale") or []
    warnings = item.get("warnings") or []
    if rationale:
        st.write("Rationale:")
        for entry in rationale:
            st.write(f"- {entry}")
    if warnings:
        st.warning("Warnings")
        for warning in warnings:
            st.write(f"- {warning}")


def _handle_classification_error(exc: Exception) -> None:
    message = str(exc)
    lowered = message.lower()
    if "invalid_api_key" in lowered or "incorrect api key" in lowered or "401" in lowered:
        st.error("Invalid OpenAI API key. Please check the key and try again.")
        return
    if "openai api key is required" in lowered:
        st.error("OpenAI API key is required. Enter it in the sidebar.")
        return
    st.error("Classification failed. Please try again.")
    with st.expander("Show error details"):
        st.write(message)


def _build_gmail_query(category: str, query: str) -> str:
    category_filter = CATEGORY_QUERY_MAP.get(category, "")
    parts = []
    if category_filter:
        parts.append(category_filter)
    if query:
        parts.append(query.strip())
    return " ".join(parts).strip()


def _get_query_param(name: str) -> str:
    if hasattr(st, "query_params"):
        value = st.query_params.get(name, "")
    else:
        value = st.experimental_get_query_params().get(name, "")
    if isinstance(value, list):
        return value[0] if value else ""
    return value or ""


def _clear_query_params() -> None:
    if hasattr(st, "query_params"):
        st.query_params.clear()
    else:
        st.experimental_set_query_params()


def _get_web_oauth_config() -> Optional[dict]:
    try:
        client_id = st.secrets.get("GOOGLE_CLIENT_ID", "")
        client_secret = st.secrets.get("GOOGLE_CLIENT_SECRET", "")
        redirect_uri = st.secrets.get("GOOGLE_REDIRECT_URI", "")
    except Exception:
        client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "")
    if client_id and client_secret and redirect_uri:
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
    return None


def _get_session_credentials(scopes: list[str]) -> Optional[Credentials]:
    creds_info = st.session_state.get("gmail_creds_json")
    if not creds_info:
        return None
    creds = Credentials.from_authorized_user_info(creds_info, scopes)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        st.session_state.gmail_creds_json = json.loads(creds.to_json())
    return creds


def _store_session_credentials(creds: Credentials) -> None:
    st.session_state.gmail_creds_json = json.loads(creds.to_json())


def _load_credentials(token_path: str, scopes: list[str]) -> Optional[Credentials]:
    if not os.path.exists(token_path):
        return None
    creds = Credentials.from_authorized_user_file(token_path, scopes)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        _save_credentials(token_path, creds)
    return creds


def _save_credentials(token_path: str, creds: Credentials) -> None:
    with open(token_path, "w", encoding="utf-8") as handle:
        handle.write(creds.to_json())


def _build_web_flow(web_config: dict) -> Flow:
    client_config = {
        "web": {
            "client_id": web_config["client_id"],
            "client_secret": web_config["client_secret"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = Flow.from_client_config(client_config, scopes=DEFAULT_SCOPES)
    flow.redirect_uri = web_config["redirect_uri"]
    return flow


def _resolve_db_path(user_email: Optional[str]) -> str:
    base_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(base_dir, exist_ok=True)
    if user_email:
        key = hashlib.sha256(user_email.lower().encode("utf-8")).hexdigest()[:12]
        return os.path.join(base_dir, f"triage_{key}.db")
    return os.path.join(base_dir, "triage_anonymous.db")


def _load_gmail_messages(credentials_path, token_path, query, max_results, page_token=None):
    # Fetch raw Gmail messages and convert them into Email objects.
    web_config = _get_web_oauth_config()
    if web_config:
        creds = _get_session_credentials(DEFAULT_SCOPES)
        if not creds:
            raise ValueError("Sign in with Gmail first.")
        service = build_gmail_service(creds)
    else:
        service = get_gmail_service(credentials_path, token_path)
    account_email = get_profile_email(service)
    messages, next_token = list_message_page(
        service, query=query, max_results=max_results, page_token=page_token
    )
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
    return items, next_token, account_email


def _try_complete_web_auth(web_config: dict) -> Optional[str]:
    code = _get_query_param("code")
    if not code:
        return None
    flow = _build_web_flow(web_config)
    flow.fetch_token(code=code)
    creds = flow.credentials
    _store_session_credentials(creds)
    _clear_query_params()
    service = build_gmail_service(creds)
    return get_profile_email(service)


def _sign_in_gmail(credentials_path: str, token_path: str) -> str:
    web_config = _get_web_oauth_config()
    if not web_config:
        service = get_gmail_service(credentials_path, token_path)
        return get_profile_email(service)
    creds = _get_session_credentials(DEFAULT_SCOPES)
    if creds:
        service = build_gmail_service(creds)
        return get_profile_email(service)
    return ""


def _reset_gmail_auth() -> None:
    if os.path.exists(TOKEN_PATH):
        os.remove(TOKEN_PATH)
    for key in ("gmail_user_email", "gmail_page_token", "gmail_query", "gmail_synced", "gmail_messages", "gmail_results"):
        st.session_state.pop(key, None)
    st.session_state.pop("gmail_creds_json", None)
    st.session_state.user_db_path = _resolve_db_path(None)


def main() -> None:
    st.set_page_config(page_title="Secure Mail Triage", page_icon=":shield:")
    st.title("Secure Mail Triage")

    # Streamlit session state holds the loaded Gmail cache and recent results.
    if "gmail_messages" not in st.session_state:
        st.session_state.gmail_messages = []
    if "gmail_results" not in st.session_state:
        st.session_state.gmail_results = []
    if "gmail_page_token" not in st.session_state:
        st.session_state.gmail_page_token = None
    if "gmail_query" not in st.session_state:
        st.session_state.gmail_query = ""
    if "gmail_synced" not in st.session_state:
        st.session_state.gmail_synced = False
    if "gmail_user_email" not in st.session_state:
        st.session_state.gmail_user_email = ""
    if "user_db_path" not in st.session_state:
        st.session_state.user_db_path = _resolve_db_path(None)
    if "oauth_started" not in st.session_state:
        st.session_state.oauth_started = False
    if "gmail_creds_json" not in st.session_state:
        st.session_state.gmail_creds_json = None

    web_config = _get_web_oauth_config()
    if web_config and not st.session_state.gmail_user_email:
        account_email = _try_complete_web_auth(web_config)
        if account_email:
            st.session_state.gmail_user_email = account_email
            st.session_state.user_db_path = _resolve_db_path(account_email)
            st.session_state.oauth_started = False

    with st.sidebar:
        st.header("Settings")
        st.text_input("OpenAI model", value=FIXED_MODEL, disabled=True)
        api_key_input = st.text_input(
            "OpenAI API key",
            type="password",
            help="Stored in session only; never written to disk.",
        )
        resolved_api_key = (api_key_input or "").strip() or os.getenv("OPENAI_API_KEY", "")
        if not resolved_api_key:
            st.warning("Enter an OpenAI API key to run classification.")
        if st.session_state.gmail_user_email:
            st.success(f"Signed in as {st.session_state.gmail_user_email}")
            if st.button("Switch Gmail account"):
                _reset_gmail_auth()
                st.rerun()
        else:
            st.info("Sign in with Gmail to use per-account storage.")
            if st.button("Sign in with Gmail"):
                st.session_state.oauth_started = True
            if web_config and st.session_state.oauth_started:
                try:
                    flow = _build_web_flow(web_config)
                    auth_url, _ = flow.authorization_url(
                        access_type="offline",
                        include_granted_scopes="true",
                        prompt="consent select_account",
                    )
                    st.link_button("Continue with Google", auth_url)
                    st.caption("After approving, you will return here automatically.")
                except Exception as exc:
                    st.error(f"Gmail sign-in failed: {exc}")
            if not web_config and st.session_state.oauth_started:
                try:
                    with st.spinner("Signing in..."):
                        account_email = _sign_in_gmail(CREDENTIALS_PATH, TOKEN_PATH)
                    st.session_state.gmail_user_email = account_email
                    st.session_state.user_db_path = _resolve_db_path(account_email)
                    st.success(f"Signed in as {account_email}")
                    st.session_state.oauth_started = False
                except Exception as exc:
                    st.error(f"Gmail sign-in failed: {exc}")
        db_path = st.text_input(
            "Storage (per account)",
            value=st.session_state.user_db_path,
            disabled=True,
        )
        store_results = st.checkbox("Store results in DB", value=True)

    gmail_tab, manual_tab, results_tab = st.tabs(["Your Emails", "Manual Input", "Recent Results"])

    with gmail_tab:
        st.subheader("Your Inbox")
        st.caption("Attachments are not analyzed; only email headers/body are classified.")

        search_query = st.text_input(
            "Search mail",
            value="",
            placeholder="Search mail",
            help="Use Gmail search operators (e.g., invoice, from:, subject:, newer_than:7d).",
            label_visibility="collapsed",
        )
        st.caption("Examples: invoice | from:amazon | subject:invoice")
        category = st.radio("Inbox category", options=list(CATEGORY_QUERY_MAP.keys()), horizontal=True)
        time_filter_label = st.selectbox("Time range", options=list(TIME_FILTERS.keys()))
        time_filter = TIME_FILTERS.get(time_filter_label, "")
        combined_query = " ".join(part for part in [search_query.strip(), time_filter] if part)
        effective_query = _build_gmail_query(category, combined_query)
        st.caption(f"Query: {effective_query or '(all mail)'}")
        sync_cols = st.columns([1, 1])
        if sync_cols[0].button("Sync inbox"):
            try:
                with st.spinner("Syncing inbox..."):
                    items, next_token, account_email = _load_gmail_messages(
                        CREDENTIALS_PATH,
                        TOKEN_PATH,
                        effective_query,
                        DEFAULT_MAX_RESULTS,
                        page_token=None,
                    )
                st.session_state.gmail_messages = items
                st.session_state.gmail_page_token = next_token
                st.session_state.gmail_query = effective_query
                st.session_state.gmail_results = []
                st.session_state.gmail_synced = True
                st.session_state.gmail_user_email = account_email
                st.session_state.user_db_path = _resolve_db_path(account_email)
                st.success(f"Loaded {len(items)} messages.")
            except Exception as exc:
                st.error(f"Gmail load failed: {exc}")

        if st.session_state.gmail_synced and sync_cols[1].button("Sync more"):
            if not st.session_state.gmail_page_token:
                st.info("No more messages to load.")
            else:
                try:
                    with st.spinner("Loading more messages..."):
                        items, next_token, account_email = _load_gmail_messages(
                            CREDENTIALS_PATH,
                            TOKEN_PATH,
                            st.session_state.gmail_query,
                            DEFAULT_MAX_RESULTS,
                            page_token=st.session_state.gmail_page_token,
                        )
                    existing_ids = {item["message_id"] for item in st.session_state.gmail_messages}
                    new_items = [item for item in items if item["message_id"] not in existing_ids]
                    st.session_state.gmail_messages.extend(new_items)
                    st.session_state.gmail_page_token = next_token
                    if account_email:
                        st.session_state.gmail_user_email = account_email
                        st.session_state.user_db_path = _resolve_db_path(account_email)
                    st.success(f"Added {len(new_items)} messages.")
                except Exception as exc:
                    st.error(f"Gmail load failed: {exc}")

        messages = st.session_state.gmail_messages
        if messages:
            label_map = {item["message_id"]: _message_label(item) for item in messages}
            options = list(label_map.keys())
            select_all = st.checkbox("Select all")
            selected_ids = st.multiselect(
                "Select emails",
                options,
                default=options if select_all else [],
                format_func=lambda mid: label_map.get(mid, mid),
            )
            if st.button("Classify selected"):
                try:
                    api_key = (api_key_input or "").strip() or os.getenv("OPENAI_API_KEY")
                    if not api_key:
                        raise ValueError("OpenAI API key is required to run classification.")
                    pipeline = _build_pipeline(api_key=api_key)
                    selected_items = [
                        item for item in messages if item["message_id"] in selected_ids
                    ]
                    results = []
                    total = len(selected_items)
                    progress = st.progress(0.0) if total else None
                    with st.spinner("Classifying selected emails..."):
                        for idx, item in enumerate(selected_items, start=1):
                            email = item["email"]
                            classification, details = pipeline.run_with_details(email)
                            results.append({"item": item, "classification": classification})
                            if store_results:
                                save_result(
                                    db_path=st.session_state.user_db_path,
                                    source="gmail_ui",
                                    message_id=item.get("message_id"),
                                    thread_id=item.get("thread_id"),
                                    email=email,
                                    classification=classification,
                                    details=details,
                                    received_at=item.get("received_at"),
                                )
                            if progress:
                                progress.progress(idx / total)
                    if progress:
                        progress.empty()
                    st.session_state.gmail_results = results
                except Exception as exc:
                    _handle_classification_error(exc)

            if st.session_state.gmail_results:
                filter_cols = st.columns([1, 1])
                show_phishing = filter_cols[0].checkbox(
                    "Show phishing results",
                    value=False,
                    key="show_phishing_gmail",
                )
                show_legit = filter_cols[1].checkbox(
                    "Show legitimate results",
                    value=False,
                    key="show_legit_gmail",
                )
                if not show_phishing:
                    st.caption("Phishing results are hidden by default; toggle to view. Hidden does not mean deleted.")
                phishing_results, legit_results = _group_results(st.session_state.gmail_results)
                if show_phishing and phishing_results:
                    st.subheader("Phishing results")
                    for result in phishing_results:
                        label = _message_label(result["item"])
                        with st.expander(label):
                            _render_result(result["classification"])
                if show_legit and legit_results:
                    st.subheader("Legitimate results")
                    for result in legit_results:
                        label = _message_label(result["item"])
                        with st.expander(label):
                            _render_result(result["classification"])
        else:
            st.info("No Gmail messages loaded yet.")

    with manual_tab:
        st.subheader("Manual Email Entry")
        st.caption("Use this to check emails copied from other inboxes or sources.")
        subject = st.text_input("Subject")
        sender = st.text_input("Sender")
        recipients_input = st.text_input("Recipients (comma-separated)")
        body = st.text_area("Body", height=200)

        if st.button("Classify manual email"):
            recipients = [r.strip() for r in recipients_input.split(",") if r.strip()]
            email = Email(subject=subject, body=body, sender=sender, recipients=recipients)
            try:
                api_key = (api_key_input or "").strip() or os.getenv("OPENAI_API_KEY")
                if not api_key:
                    raise ValueError("OpenAI API key is required to run classification.")
                pipeline = _build_pipeline(api_key=api_key)
                with st.spinner("Classifying..."):
                    classification, details = pipeline.run_with_details(email)
                    _render_result(classification)
                    if store_results:
                        save_result(
                            db_path=st.session_state.user_db_path,
                            source="ui",
                            message_id=None,
                            thread_id=None,
                            email=email,
                            classification=classification,
                            details=details,
                        )
            except Exception as exc:
                _handle_classification_error(exc)

    with results_tab:
        st.subheader("Recent Results")
        if "recent_results" not in st.session_state:
            st.session_state.recent_results = []
        if st.button("Refresh"):
            st.session_state.recent_results = fetch_recent_results(
                st.session_state.user_db_path, limit=100
            )

        results = st.session_state.recent_results
        if results:
            phishing_count = sum(1 for item in results if str(item.get("verdict", "")).lower() == "phishing")
            total_count = len(results)
            legit_count = total_count - phishing_count
            cols = st.columns(3)
            cols[0].metric("Total analyzed", total_count)
            cols[1].metric("Phishing", phishing_count)
            cols[2].metric("Legitimate", legit_count)

            st.subheader("Verdict breakdown")
            st.bar_chart({"Phishing": [phishing_count], "Legitimate": [legit_count]})

            filter_cols = st.columns([1, 1])
            show_phishing = filter_cols[0].checkbox(
                "Show phishing results",
                value=False,
                key="show_phishing_recent",
            )
            show_legit = filter_cols[1].checkbox(
                "Show legitimate results",
                value=False,
                key="show_legit_recent",
            )
            if not show_phishing:
                st.caption("Phishing results are hidden by default; toggle to view. Hidden does not mean deleted.")

            phishing_items = [item for item in results if str(item.get("verdict", "")).lower() == "phishing"]
            legit_items = [item for item in results if str(item.get("verdict", "")).lower() != "phishing"]

            phishing_items.sort(key=lambda item: int(item.get("risk_score", 0) or 0), reverse=True)
            legit_items.sort(key=lambda item: int(item.get("risk_score", 0) or 0), reverse=True)

            st.subheader("Top sender domains")
            domain_counts: dict[str, int] = {}
            domain_phishing: dict[str, bool] = {}
            for item in results:
                sender = item.get("sender") or ""
                _, email_addr = parseaddr(sender)
                if "@" in email_addr:
                    domain = email_addr.split("@", 1)[1].lower()
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
                    if str(item.get("verdict", "")).lower() == "phishing":
                        domain_phishing[domain] = True
            top_domains = sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)[:10]
            if top_domains:
                for domain, count in top_domains:
                    if domain_phishing.get(domain):
                        st.markdown(f"- <span style='color:red'>{domain}</span> ({count})", unsafe_allow_html=True)
                    else:
                        st.markdown(f"- {domain} ({count})")
            else:
                st.caption("No sender domains available.")

            if show_phishing and phishing_items:
                st.subheader("Phishing results")
                for item in phishing_items:
                    with st.expander(item.get("subject") or "(no subject)"):
                        _render_recent_item(item)

            if show_legit and legit_items:
                st.subheader("Legitimate results")
                for item in legit_items:
                    with st.expander(item.get("subject") or "(no subject)"):
                        _render_recent_item(item)
        else:
            st.info("No results found.")


if __name__ == "__main__":
    main()
