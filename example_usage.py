"""Demonstration of the multi-agent classification pipeline."""  # Module-level docstring describing the purpose of this example script.
import logging  # Built-in logging to show pipeline progress.
from pprint import pprint  # Pretty-print helper for displaying structured results.

from secure_mail_triage.agents import Email  # Import the Email dataclass used to model input messages.
from secure_mail_triage.pipeline import ClassificationPipeline  # Import the orchestrating pipeline class.

logging.basicConfig(level=logging.INFO)  # Configure logging to emit informational messages.

sample_emails = [  # Define a small list of sample emails to feed into the pipeline.
    Email(  # Construct the first sample email instance.
        subject="Urgent: Verify your account immediately",  # Subject line containing urgency wording.
        body="Your account will be suspended. Click here to confirm: http://secure-login.example.com",  # Body with a phishing-style link.
        sender="alert@example.com",  # Sender address for the first email.
        recipients=["user@example.org"],  # List of recipients for the first email.
    ),
    Email(  # Construct the second sample email instance.
        subject="Team lunch reminder",  # Benign subject line for a reminder.
        body="Don't forget our team lunch at noon in the cafeteria. See you!",  # Friendly, low-risk body content.
        sender="hr@company.com",  # Sender address treated as trusted in the allow list.
        recipients=["user@example.org"],  # Recipient list for the second email.
    ),
    Email(  # Construct the third sample email instance.
        subject="Invoice for your recent purchase",  # Subject suggesting a billing message.
        body="Please see attached invoice for your order.",  # Body referencing an attachment.
        sender="billing@vendor.com",  # Sender address for the invoice email.
        recipients=["ap@company.com", "ap@company.com"],  # Duplicate recipients to trigger anomaly detection.
        attachments=[{"name": "invoice.js"}],  # Suspicious JavaScript attachment to test risk scoring.
    ),
]

reputation = {"secure-login.example.com": "bad"}  # Minimal reputation hints marking a risky domain.
pipeline = ClassificationPipeline(  # Initialize the classification pipeline with context settings.
    reputation=reputation,  # Pass reputation hints to the link and attachment safety agent.
    allow_senders=["hr@company.com"],  # Treat the HR sender as lower risk.
    block_senders=["spoofed@evil.com"],  # Explicitly block a known malicious sender.
    allow_domains=["company.com"],  # Allowlist the corporate domain for reduced risk.
)

if __name__ == "__main__":  # Execute the demo when the script is run directly.
    for i, email in enumerate(sample_emails, start=1):  # Iterate through each sample email with a counter.
        print(f"\n=== Email {i}: {email.subject} ===")  # Print a header identifying the current email.
        result = pipeline.run(email)  # Run the pipeline and obtain the aggregated classification result.
        pprint(result.features)  # Pretty-print the core features, including verdict and rationale.
        if result.warnings:  # If any warnings were raised during processing...
            print("Warnings:", result.warnings)  # ...display them for observability.
