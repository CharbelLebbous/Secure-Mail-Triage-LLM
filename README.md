# Secure Mail Triage

Agentic workflow design for classifying and triaging phishing emails. The focus is a multi-agent classification pipeline that keeps decisions explainable, observable, and easy to extend.

## Problem description
Phishing emails remain a top initial access vector. Manual review is slow and inconsistent, which delays response and increases risk. This project designs an agentic workflow that classifies incoming messages as phishing or legitimate using specialized agents and a final aggregation step.

## Agentic classification workflow
The pipeline decomposes classification into small, testable agents and a simple aggregator.

1. **Email Structure Agent** – normalizes headers/body, extracts URLs/domains, enforces size/attachment limits, and outputs structured fields for downstream agents.
2. **Tone & Intent Agent** – scores urgency, coercion, and impersonation cues in the normalized body text.
3. **Content Policy Agent** – flags credential harvest attempts, payment/transfer asks, and PII collection with detected term spans.
4. **Link & Attachment Safety Agent** – evaluates domains against reputation hints and heuristic TLD/IP checks; scores risky attachments (executables, encrypted files).
5. **User/Org Context Agent** – applies allow/block lists and simple anomalies (duplicate recipients) to adjust risk.
6. **Classification Aggregator** – fuses all agent outputs into a risk score and verdict, carrying forward warnings for observability/guardrails.

### Data flow
- Intake via **Email Structure Agent** → tone, content, link/attachment safety, and user/org context agents → **Classification Aggregator**.
- Each agent returns structured `features` and `warnings` that remain visible in the final result for debugging and auditability.

### Observability & guardrails
- Guardrails: input validation and limits (body length, attachment count) to prevent pathological inputs from derailing classification.
- Observability: agents emit structured data and warnings; the aggregator surfaces a rationale list summarizing why risk increased.

## Quickstart
Run the example script to see the multi-agent pipeline in action:

```bash
python example_usage.py
```

Expected output (similar to):
```
=== Email 1: Urgent: Verify your account immediately ===
{'rationale': ['Urgent language detected', 'Requests credentials', 'Risky domains detected'],
 'risk_score': 7,
 'verdict': 'phishing'}

=== Email 2: Team lunch reminder ===
{'rationale': [], 'risk_score': -2, 'verdict': 'legitimate'}

=== Email 3: Invoice for your recent purchase ===
{'rationale': ['Requests payment/transfer', 'Risky attachment: invoice.js', 'Duplicate recipients anomaly'],
 'risk_score': 6,
 'verdict': 'phishing'}
Warnings: ['Duplicate recipients detected']
```

You can adjust allow/block lists, reputation hints, and the phishing threshold inside `ClassificationPipeline` to match your environment.
