"""Demonstration of the multi-agent classification pipeline."""
import logging
from pprint import pprint

from secure_mail_triage.agents import Email
from secure_mail_triage.pipeline import ClassificationPipeline

logging.basicConfig(level=logging.INFO)

sample_emails = [
    Email(
        subject="Urgent: Verify your account immediately",
        body="Your account will be suspended. Click here to confirm: http://secure-login.example.com",
        sender="alert@example.com",
        recipients=["user@example.org"],
    ),
    Email(
        subject="Team lunch reminder",
        body="Don't forget our team lunch at noon in the cafeteria. See you!",
        sender="hr@company.com",
        recipients=["user@example.org"],
    ),
    Email(
        subject="Invoice for your recent purchase",
        body="Please see attached invoice for your order.",
        sender="billing@vendor.com",
        recipients=["ap@company.com", "ap@company.com"],
        attachments=[{"name": "invoice.js"}],
    ),
]

reputation = {"secure-login.example.com": "bad"}
pipeline = ClassificationPipeline(
    reputation=reputation,
    allow_senders=["hr@company.com"],
    block_senders=["spoofed@evil.com"],
    allow_domains=["company.com"],
)

if __name__ == "__main__":
    for i, email in enumerate(sample_emails, start=1):
        print(f"\n=== Email {i}: {email.subject} ===")
        result = pipeline.run(email)
        pprint(result.features)
        if result.warnings:
            print("Warnings:", result.warnings)
