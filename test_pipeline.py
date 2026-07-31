from app.engines.orchestrator import run_phishing_analysis_pipeline

raw_email = b"""Subject: Urgent: Verify Your Microsoft 365 Account Immediately
From: IT Security Support <admin@microsoft-support.xyz>
To: employee@enterprise.com
Date: Tue, 29 Jul 2026 12:00:00 +0000
Message-ID: <test-12345@phish.local>
Authentication-Results: spf=fail dkim=fail dmarc=fail
Content-Type: text/plain; charset="utf-8"

Dear Employee,

Your Microsoft 365 account has been locked due to suspicious login attempts. You must verify your credentials immediately within 24 hours or your mailbox will be terminated.

Click here to sign in: http://phishing-secure-login.com/auth/verify?user=employee

Regards,
Microsoft IT Security Team
"""

result = run_phishing_analysis_pipeline(raw_email, "test_phish.eml")
print("Analysis ID:", result["analysis_id"])
print("Risk Score:", result["scoring"]["risk_score"])
print("Severity:", result["scoring"]["severity"])
print("Verdict:", result["scoring"]["verdict"])
print("Behavior:", result["behavior"]["behavior_classification"])
print("Supporting Evidence Count:", len(result["correlation"]["supporting_evidence"]))
print("Pipeline Test Passed Successfully!")
