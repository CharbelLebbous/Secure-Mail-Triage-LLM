# Secure Mail Triage

Agentic workflow design for classifying and triaging phishing emails. The goal is to automate first-pass review, produce clear explanations, and recommend safe handling actions.

## Problem description
Phishing emails remain a top initial access vector. Manual review is slow and inconsistent, which delays response and increases risk. This project designs a LangChain-based workflow that classifies incoming messages as phishing or legitimate, explains the decision, and proposes an action (quarantine, warn the user, or allow).

## Agentic workflow (text design)
**Inputs**
- Email content (subject, body, minimal headers)
- Optional sender/domain reputation snippets and URL expansions (kept inline in the notebook)

**Outputs**
- Classification label: `phishing` or `legitimate`
- Explanation: short rationale citing risky indicators (suspicious links, spoofed domains, urgent language)
- Action recommendation: quarantine, warn user, or allow

### Agents and roles
1. **Intake & normalization agent**
   - Cleans the raw email (strip HTML/trackers), extracts URLs/domains, and normalizes text for downstream use.
2. **Classification agent**
   - Uses a prompt-or-LLM-based classifier to label the email. Optionally consults a tiny in-notebook reputation map for known bad domains.
3. **Explanation agent**
   - Summarizes the key risky or benign signals behind the classification. Outputs bullet points suitable for analyst review.
4. **Action recommender agent**
   - Maps the classification + explanation to an action: quarantine, warn user, or allow. Includes a short justification and confidence.

### Data flow
- Intake agent -> Classification agent (uses normalized text + optional reputation hints)
- Classification result + extracted indicators -> Explanation agent -> Action recommender agent
- Outputs are assembled into a response object for easy display/logging in the notebook.

### Configuration notes
- Keep all sample emails and reputation hints inline as Python variables so the notebook has no external data dependencies.
- Prefer lightweight local or API LLMs already accessible in Colab (e.g., `gpt-4o-mini` or open-source instruct models) with simple LangChain tools.
- Use deterministic parsing functions (regex/standard library) to keep preprocessing reliable.

### Next implementation steps (for the Colab)
- Set up a small synthetic dataset of phishing vs. legitimate emails directly in a cell.
- Implement the agents with LangChain chains or tools, plus simple rule-based helpers for URL/domain extraction.
- Add an evaluation cell that runs a few sample emails through the pipeline and prints the classification, explanation, and action.

## Colab notebook scaffold (OpenAI API)
Use `COLAB_TEMPLATE.md` as a cell-by-cell guide to build the notebook quickly with the OpenAI API:
- Inline dataset and reputation hints (no external downloads)
- Helper functions for normalization and URL/domain extraction
- Prompts for classification, explanation, and action recommendation
- LangChain chains wired to an OpenAI chat model you can access (default `gpt-4o-mini`)
- Evaluation cells to print results and a quick accuracy check

**Notes for OpenAI setup**
- The ChatGPT Plus web subscription does **not** include API credits; you need an OpenAI API key with quota.
- In Colab, set `OPENAI_API_KEY` (e.g., via `os.environ["OPENAI_API_KEY"] = "..."`).
- Keep prompts concise to control token usage; set `temperature=0` for consistency.
- If you use a different OpenAI model (e.g., `gpt-3.5-turbo` or `gpt-4o`), update the `OPENAI_MODEL` variable in the template.
