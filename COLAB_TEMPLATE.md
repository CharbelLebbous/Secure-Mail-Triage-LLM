# Secure Mail Triage — Colab notebook scaffold

This template mirrors the agentic workflow described in the README. Copy the cells into a new Colab notebook and run them sequentially. Keep the sample data inline to avoid external dependencies.

## 1) Setup (OpenAI API)
```python
!pip install -q langchain langchain-openai langchain-community openai

import os
# Store your OpenAI key in Colab secrets for safety, or paste temporarily while testing.
os.environ["OPENAI_API_KEY"] = "<YOUR_OPENAI_KEY>"

# Pick any OpenAI chat model available to your account.
OPENAI_MODEL = "gpt-4o-mini"
```

## 2) Sample inline dataset
A tiny, fully inline dataset—no downloads. Feel free to add more examples.
```python
sample_emails = [
    {
        "id": "p1",
        "subject": "Urgent: Verify your account immediately",
        "body": "Your account will be suspended. Click here to confirm: http://secure-login.example.com",
        "label": "phishing",
    },
    {
        "id": "p2",
        "subject": "Invoice for your recent purchase",
        "body": "Please see attached invoice for your order. Contact us if questions.",
        "label": "legitimate",
    },
    {
        "id": "p3",
        "subject": "Password Reset Notification",
        "body": "We noticed a login attempt. Reset your password here: http://account-security.example.net",
        "label": "phishing",
    },
    {
        "id": "p4",
        "subject": "Team lunch reminder",
        "body": "Don’t forget our team lunch at noon in the cafeteria. See you!",
        "label": "legitimate",
    },
]

# Simple reputation hints kept inline
reputation = {
    "example.com": "bad",
    "example.net": "bad",
    "example.org": "neutral",
}
```

## 3) Lightweight helpers (URL extraction, normalization)
```python
import re
from urllib.parse import urlparse

def extract_urls(text: str):
    return re.findall(r"https?://[^\s]+", text)

def extract_domains(urls):
    domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc.lower())
    return domains

def normalize_email(subject: str, body: str):
    # Simple normalization; extend as needed
    text = f"Subject: {subject}\n\n{body}".strip()
    urls = extract_urls(text)
    domains = extract_domains(urls)
    return {"text": text, "urls": urls, "domains": domains}
```

## 4) Prompts and LangChain setup (OpenAI)
```python
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Use an OpenAI chat model available to your account (default "gpt-4o-mini").
llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0)

classification_prompt = ChatPromptTemplate.from_template(
    """
    You classify emails as phishing or legitimate.
    Consider URLs, domains, urgency, and requests for credentials.
    If reputation hints mark a domain as bad, treat it as high risk.

    Email:
    {email_text}
    URLs: {urls}
    Domains: {domains}
    Reputation: {reputation}

    Respond with a single word: phishing or legitimate.
    """
)

explanation_prompt = ChatPromptTemplate.from_template(
    """
    You are an analyst summarizing why an email was classified as {label}.
    Provide 3-5 bullet points citing risky or benign indicators.

    Email:
    {email_text}
    URLs: {urls}
    Domains: {domains}
    Reputation: {reputation}
    """
)

action_prompt = ChatPromptTemplate.from_template(
    """
    Recommend an action based on the classification and explanation.
    Actions: quarantine, warn user, or allow.

    Classification: {label}
    Explanation:
    {explanation}

    Respond with a short JSON object:
    {{"action": "<quarantine|warn|allow>", "justification": "<short reason>"}}
    """
)
```

## 5) Chains
```python
from langchain_core.runnables import RunnablePassthrough

classifier = classification_prompt | llm | StrOutputParser()
explainer = explanation_prompt | llm | StrOutputParser()
actioner = action_prompt | llm | StrOutputParser()

def run_pipeline(email, reputation):
    normalized = normalize_email(email["subject"], email["body"])
    label = classifier.invoke({
        "email_text": normalized["text"],
        "urls": normalized["urls"],
        "domains": normalized["domains"],
        "reputation": reputation,
    }).strip().lower()

    explanation = explainer.invoke({
        "label": label,
        "email_text": normalized["text"],
        "urls": normalized["urls"],
        "domains": normalized["domains"],
        "reputation": reputation,
    })

    action = actioner.invoke({
        "label": label,
        "explanation": explanation,
    })

    return {"id": email["id"], "label": label, "explanation": explanation, "action": action}
```

## 6) Run and inspect results
```python
results = [run_pipeline(email, reputation) for email in sample_emails]
for r in results:
    print("\n=== Email", r["id"], "===")
    print("Label:", r["label"])
    print("Explanation:\n", r["explanation"])
    print("Action:", r["action"])
```

## 7) Optional: simple accuracy check
```python
import json
correct = 0
for email, result in zip(sample_emails, results):
    if result["label"] == email["label"]:
        correct += 1
print(f"Accuracy on sample set: {correct}/{len(sample_emails)}")
print(json.dumps(results, indent=2))
```

## 8) Notes for submission
- Keep the dataset inline as above.
- If you want to avoid OpenAI usage, you can swap `ChatOpenAI` with a local or open-weight model (e.g., `langchain.llms.LlamaCpp` or Hugging Face TGI) while keeping the same prompts and chain wiring.
- Share the notebook with `francis.elhelou@gmail.com` before submission.
