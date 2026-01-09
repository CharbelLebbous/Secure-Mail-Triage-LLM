"""SQLite persistence for triage results.

Usage notes:
- Used by CLI/UI when storing results for audit and review.
- Optional; skip with --no-store in CLI or unchecked in UI.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Iterable, List, Optional

from .agents import AgentResult, Email


def _agent_result_to_dict(result: AgentResult) -> Dict[str, Any]:
    return {"name": result.name, "features": result.features, "warnings": result.warnings}


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        # Create schema once; safe to call on every write.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                message_id TEXT,
                thread_id TEXT,
                subject TEXT,
                sender TEXT,
                recipients TEXT,
                received_at TEXT,
                risk_score INTEGER,
                verdict TEXT,
                rationale TEXT,
                warnings TEXT,
                agent_outputs TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_message_id ON email_results(message_id)"
        )
        conn.commit()
    finally:
        conn.close()


def save_result(
    db_path: str,
    source: str,
    message_id: Optional[str],
    thread_id: Optional[str],
    email: Email,
    classification: AgentResult,
    details: Dict[str, AgentResult],
    received_at: Optional[str] = None,
) -> None:
    init_db(db_path)
    # Persist the full agent outputs for later review and audit.
    agent_outputs = {name: _agent_result_to_dict(result) for name, result in details.items()}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO email_results (
                source,
                message_id,
                thread_id,
                subject,
                sender,
                recipients,
                received_at,
                risk_score,
                verdict,
                rationale,
                warnings,
                agent_outputs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source,
                message_id,
                thread_id,
                email.subject,
                email.sender,
                json.dumps(email.recipients),
                received_at,
                int(classification.features.get("risk_score", 0)),
                classification.features.get("verdict", ""),
                json.dumps(classification.features.get("rationale", [])),
                json.dumps(classification.warnings),
                json.dumps(agent_outputs),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_recent_results(db_path: str, limit: int = 50) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT source, message_id, thread_id, subject, sender, recipients, received_at,
                   risk_score, verdict, rationale, warnings, created_at
            FROM email_results
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        results: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            # Convert JSON fields back into Python values for display.
            for field in ("recipients", "rationale", "warnings"):
                if item.get(field):
                    try:
                        item[field] = json.loads(item[field])
                    except json.JSONDecodeError:
                        pass
            results.append(item)
        return results
    finally:
        conn.close()
