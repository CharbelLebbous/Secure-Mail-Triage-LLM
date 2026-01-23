"""Gmail ingestion helpers using the Gmail API.

Usage notes:
- Used by both the CLI and the Streamlit UI for Gmail ingestion.
- Attachments are not analyzed; only a count is recorded.
"""
from __future__ import annotations

import base64
import os
import re
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Dict, Iterable, List, Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from .agents import Email

DEFAULT_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _decode_header_value(value: str) -> str:
    parts = decode_header(value or "")
    decoded: List[str] = []
    for text, charset in parts:
        if isinstance(text, bytes):
            decoded.append(text.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(text))
    return "".join(decoded)


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def _extract_body(message) -> str:
    if message.is_multipart():
        plain_parts: List[str] = []
        html_parts: List[str] = []
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            if content_disposition == "attachment":
                continue
            # Decode each text part safely, falling back to utf-8 if needed.
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, AttributeError):
                text = payload.decode("utf-8", errors="replace")
            if content_type == "text/plain":
                plain_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(text)
        if plain_parts:
            return "\n".join(plain_parts).strip()
        if html_parts:
            # Only use HTML if no plain text part is present.
            return _strip_html("\n".join(html_parts)).strip()
        return ""
    payload = message.get_payload(decode=True)
    if not payload:
        return ""
    charset = message.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace").strip()
    except (LookupError, AttributeError):
        return payload.decode("utf-8", errors="replace").strip()


def _count_attachments(message) -> int:
    count = 0
    for part in message.walk():
        filename = part.get_filename()
        content_disposition = part.get_content_disposition()
        if filename or content_disposition == "attachment":
            count += 1
    return count


def get_gmail_service(
    credentials_path: str,
    token_path: str,
    scopes: Optional[Iterable[str]] = None,
):
    scopes = list(scopes) if scopes else DEFAULT_SCOPES
    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, scopes)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh without re-prompting if we have a refresh token.
            creds.refresh(Request())
        else:
            # First-time auth flow writes token.json locally.
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w", encoding="utf-8") as handle:
            handle.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def build_gmail_service(creds):
    """Build a Gmail API service from existing credentials."""
    return build("gmail", "v1", credentials=creds)


def list_message_ids(service, user_id: str = "me", query: Optional[str] = None, max_results: int = 10):
    messages: List[Dict[str, str]] = []
    page_token = None
    while len(messages) < max_results:
        # Gmail API uses pagination; keep pulling until we hit max_results.
        response = (
            service.users()
            .messages()
            .list(userId=user_id, q=query, maxResults=min(100, max_results - len(messages)), pageToken=page_token)
            .execute()
        )
        messages.extend(response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return messages


def list_message_page(
    service,
    user_id: str = "me",
    query: Optional[str] = None,
    max_results: int = 10,
    page_token: Optional[str] = None,
) -> Tuple[List[Dict[str, str]], Optional[str]]:
    """Fetch a single page of message IDs plus the next page token."""
    response = (
        service.users()
        .messages()
        .list(userId=user_id, q=query, maxResults=max_results, pageToken=page_token)
        .execute()
    )
    return response.get("messages", []), response.get("nextPageToken")


def fetch_message_raw(service, message_id: str, user_id: str = "me") -> Tuple[bytes, Dict[str, str]]:
    message = service.users().messages().get(userId=user_id, id=message_id, format="raw").execute()
    raw_data = message.get("raw", "")
    decoded = base64.urlsafe_b64decode(raw_data.encode("utf-8"))
    metadata = {
        "message_id": message.get("id"),
        "thread_id": message.get("threadId"),
        "internal_date": message.get("internalDate"),
    }
    return decoded, metadata


def get_profile_email(service, user_id: str = "me") -> str:
    """Return the Gmail account email for the authenticated user."""
    profile = service.users().getProfile(userId=user_id).execute()
    return str(profile.get("emailAddress") or "")


def parse_gmail_message(raw_bytes: bytes) -> Tuple[Email, Optional[str]]:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    headers = {k: _decode_header_value(v) for k, v in message.items()}
    subject = _decode_header_value(message.get("subject", ""))
    sender = _decode_header_value(message.get("from", ""))
    to_list = [addr for _, addr in getaddresses(message.get_all("to", []))]
    cc_list = [addr for _, addr in getaddresses(message.get_all("cc", []))]
    bcc_list = [addr for _, addr in getaddresses(message.get_all("bcc", []))]
    recipients = [addr for addr in (to_list + cc_list + bcc_list) if addr]
    body = _extract_body(message)
    attachment_count = _count_attachments(message)
    email = Email(
        subject=subject,
        body=body,
        sender=sender,
        recipients=recipients,
        headers=headers,
        attachments=[],
        attachment_count=attachment_count,
    )
    received_at = None
    if message.get("date"):
        try:
            received_at = parsedate_to_datetime(message.get("date")).isoformat()
        except (TypeError, ValueError):
            received_at = None
    return email, received_at
