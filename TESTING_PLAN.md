# Week 8 Testing Plan

## Goal
The goal for Week 8 is to develop a testing approach that measures both AI performance and security robustness for the IAM drift detection system. The plan focuses on verifying that the application detects IAM changes correctly, produces useful AI recommendations, and remains secure when handling normal, risky, and malicious inputs.

## Test Scenarios
- Functional testing: verify that added users, removed users, and policy changes are detected correctly and displayed in the dashboard.
- AI evaluation: verify that AI recommendations match the drift event, use the correct severity level, and provide specific actions instead of generic advice.
- Security testing: verify that the system handles malformed JSON, prompt injection attempts, unsafe policy text, and dependency vulnerabilities.

## Success Metrics
- Drift results match the expected output for each test case.
- AI recommendations are accurate, relevant, and grounded in the input data.
- Severity labels are consistent with the actual risk of the IAM change.
- No unresolved critical or high-severity security issues remain after testing.

## Tools
- `pytest` for functional and integration testing
- `bandit` for Python security scanning
- `pip-audit` for dependency vulnerability checks
- `semgrep` for static code analysis
- `gitleaks` for secret scanning
- Flask test client for API and dashboard response testing

## AI Validation Strategy
AI validation will use a set of sample drift cases that include low-risk, high-risk, and malformed examples. Each output will be compared against expected severity, correctness, and usefulness. Testers will check whether the AI stays grounded in the provided drift data, avoids hallucinations, and gives policy-specific remediation steps.

## Cybersecurity Auditing Strategy
Cybersecurity auditing will include vulnerability scanning, dependency review, and adversarial input testing. The team will test malformed JSON, suspicious policy content, and prompt injection attempts to see whether the system fails safely. Logs, API responses, and local configuration will also be reviewed to confirm that sensitive information is not exposed.

## Test Data and Documentation Plan
Test data will be gathered from sample baseline and current IAM snapshots, along with custom high-risk and malformed policy cases. Each test case will be documented with a test ID, purpose, input, expected result, actual result, and pass/fail outcome. This documentation will provide clear evidence of both AI performance and system security testing.
