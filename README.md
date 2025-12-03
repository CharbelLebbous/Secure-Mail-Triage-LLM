# Secure Mail Triage

Agentic workflow design for classifying and triaging phishing emails. The goal is to automate first-pass review, produce clear explanations, and recommend safe handling actions.

## Problem description
Phishing emails remain a top initial access vector. Manual review is slow and inconsistent, which delays response and increases risk. This project designs an agentic workflow that classifies incoming messages as phishing or legitimate, explains the decision, and proposes an action (quarantine, warn the user, or allow).

## Agentic workflow design
### Inputs
- Email content: subject, body, and minimal headers
- Extracted indicators: URLs, domains, and sender metadata
- Optional reputation hints: inline lookups for known-bad domains or URLs

### Outputs
- Classification: `phishing` or `legitimate`
- Explanation: short rationale citing risky or benign indicators
- Action recommendation: quarantine, warn user, or allow

### Agents and roles
1. **Intake & normalization agent** – cleans the raw email (strip HTML/trackers), extracts URLs/domains, and normalizes text for downstream use.
2. **Classification agent** – labels the email using an LLM prompt or lightweight rules; optionally consults a reputation map for known bad domains.
3. **Explanation agent** – summarizes the key signals behind the classification as analyst-friendly bullet points.
4. **Action recommender agent** – maps the classification and explanation to an action (quarantine, warn user, or allow) with a brief justification.

### Data flow
- Intake/normalization → Classification (uses normalized text + optional reputation hints)
- Classification result + extracted indicators → Explanation → Action recommendation
- Outputs assembled into a response object for display/logging.

### Configuration notes
- Keep sample emails and reputation hints inline so the workflow has no external data dependencies.
- Favor deterministic preprocessing (regex/standard library) to ensure consistent inputs.
- Use low-temperature prompts for reproducible classifications and explanations.
