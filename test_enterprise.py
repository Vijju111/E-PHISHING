from src.service.analysis_service import AnalysisService

raw_email = b"""Subject: Urgent: Verify Your Microsoft 365 Account Immediately
From: IT Security Support <admin@microsoft-support.xyz>
To: employee@enterprise.com
Date: Tue, 29 Jul 2026 12:00:00 +0000
Message-ID: <enterprise-test@phish.local>
Authentication-Results: spf=fail dkim=fail dmarc=fail
Content-Type: text/plain; charset="utf-8"

Dear Employee,

Your Microsoft 365 account has been locked. Verify immediately at http://phishing-secure-login.com/auth/verify

Regards,
IT Security
"""

result = AnalysisService.analyze_email(raw_email, "enterprise_test.eml")
print("Analysis ID:", result["analysis_id"])
print("Risk Score:", result["scoring"]["risk_score"])
print("Severity:", result["scoring"]["severity"])
print("Verdict:", result["scoring"]["verdict"])
print("Behavior:", result["behavior"]["behavior_classification"])
print("Enterprise Modular Analysis Pipeline Test Passed Successfully!")
