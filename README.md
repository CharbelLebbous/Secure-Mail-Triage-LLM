# Secure Mail Triage LLM

LLM agentic workflow for classifying and triaging phishing emails with Gmail ingestion, a UI-first experience, and SQLite audit storage. The pipeline keeps decisions explainable and easy to extend while relying on OpenAI-powered agents.

## Problem description

Phishing emails remain a top initial access vector. Manual review is slow and inconsistent, which delays response and increases risk. This project implements an LLM agentic workflow that classifies incoming messages as phishing or legitimate using specialized LLM agents and a final aggregation step, with Gmail ingestion and persistent audit logs.

## Agentic classification workflow

The pipeline decomposes classification into small, specialized LLM agents plus a final aggregator, with a rule-based link safety check (attachments are not analyzed).

1. **Email Structure Extractor (deterministic)** -> normalizes headers/body, extracts URLs/domains, and outputs structured fields.
2. **Tone & Intent LLM Agent** -> scores urgency, coercion, and impersonation cues in the normalized body text.
3. **Content Policy LLM Agent** -> flags credential harvest attempts, payment/transfer asks, and PII collection with detected term spans.
4. **Link Safety Agent (rules)** -> evaluates domains using heuristics (no attachment analysis).
5. **User/Org Context LLM Agent** -> applies allow/block lists and simple anomalies (duplicate recipients) to adjust risk.
6. **LLM Aggregator** -> fuses all agent outputs into a risk score and verdict with rationale.

### Data flow

- Intake via **Email Structure Extractor** -> LLM agents (tone, content, context) + rule-based link safety -> **LLM Aggregator**.
- Each agent returns structured `features` and `warnings` that remain visible in the final result for debugging and auditability.

### Observability & guardrails

- Guardrails: input validation and limits (body length) to prevent pathological inputs from derailing classification.
- Observability: agents emit structured data and warnings; the aggregator surfaces a rationale list summarizing why risk increased.

### Allow/block lists

Edit `secure_mail_triage/config.py` to add trusted senders/domains (allowlist) or known bad senders (blocklist). The file ships with placeholder `.example` entries; replace them with your real values.

## Setup (ML agentic pipeline + Gmail)

Install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Set your OpenAI key:

```bash
# PowerShell
$env:OPENAI_API_KEY="your_key_here"
```

The UI uses a fixed model (`gpt-4o-mini`). The CLI can override the model with `--model` if needed.

## ML agentic quickstart (LLM agents)

Classify a single email from text using LLM-backed agents:

```bash
python -m secure_mail_triage.cli text --subject "Test" --body "Please verify your account"
```

## Gmail ingestion

1. Create a Google Cloud project and enable the Gmail API.
2. Create OAuth client credentials (Desktop app) and download `credentials.json`.
3. Place `credentials.json` in the repo root (or pass `--credentials`).
4. Run:

```bash
python -m secure_mail_triage.cli gmail --query "newer_than:7d" --max-results 5
```

The first run opens a browser for OAuth and writes `token.json`.

You can also use the Gmail tab in the UI to load and select messages for classification. The UI includes a category dropdown (All/Primary/Promotions/Social/Updates) plus an optional query box.

## Data persistence

Results are stored in SQLite (default `triage.db`) with verdicts, rationale, and agent outputs.
You can change the location with `--db`.

## UI (Streamlit)

Run a lightweight UI for manual triage and viewing recent results:

```bash
streamlit run secure_mail_triage/ui_app.py
```

The UI uses the fixed model `gpt-4o-mini` and reads `OPENAI_API_KEY` from the environment.

Screenshots:

![Gmail Tab](docs/ui-gmail-tab.png)
![Classification Result](docs/ui-classification-result.png)
![Manual Input Tab](docs/ui-manual-input.png)
![Recent Results Tab](docs/ui-recent-results.png)

In the Gmail tab, pick a category (or All), optionally add a Gmail query, select one or more emails, and click classify.

## Notes

- LLM mode sends email content to the OpenAI API. Use only with permission and avoid sensitive data when required.
- Attachments are not analyzed or sent to the LLM; only a count is recorded.

## Ethical AI Considerations

| Consideration | Implementation level | Why |
| --- | --- | --- |
| Transparency & Explainability | High | Verdicts include rationales and structured agent outputs are visible in the UI/CLI. |
| Accountability & Auditability | High | Results and agent outputs can be stored in SQLite for review and tracing. |
| Robustness & Safety (prompt injection) | Medium | Prompts treat email text as untrusted and JSON mode is enforced. |
| Privacy & Data Protection | Low | Email content is sent to OpenAI; no private sandbox or redaction layer. |
| Legal & Regulatory Compliance | Low | No formal compliance mapping or retention policy is implemented (GDPR, retention policy, etc.). |
