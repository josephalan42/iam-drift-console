# Test Results

## Overview
The following tests and scans were run to provide grading evidence for AI performance and security robustness.

## Test Case Summary

| Test ID | Test | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| TC-01 | Drift detection script run | Drift report is generated successfully | `drift_report.json` generated with 3 detected changes | Pass |
| TC-02 | AI recommendation script run | Recommendation file is generated successfully | `drift_recommendations.json` generated with 3 recommendations | Pass |
| TC-03 | Pytest smoke tests | Core logic and API smoke tests pass | `3 passed, 1 warning` | Pass |
| TC-04 | Bandit security scan | No critical issues preferred | 1 high issue, 14 low issues found | Needs review |
| TC-05 | Dependency vulnerability scan | No known package vulnerabilities | 1 known Flask vulnerability found | Needs review |
| TC-06 | Semgrep static scan | Tool runs successfully | Blocked: native Windows support issue | Not run |
| TC-07 | Gitleaks secret scan | Tool runs successfully | Blocked: `gitleaks` not installed in environment | Not run |

## Command Evidence

### 1. Pytest
Command:

```powershell
python -m pytest -q
```

Result:

```text
3 passed, 1 warning in 1.57s
```

Warning noted:
- `dashboard_app.py` uses `datetime.utcnow()`, which is deprecated in Python 3.13.

### 2. Drift Detector
Command:

```powershell
python iam_drift_detector.py
```

Result:

```text
[OK] Drift report written to: D:\test_work\project_test\drift_report.json
{
  "added_users": ["new_test", "test", "web_test"],
  "removed_users": [],
  "num_changes": 3,
  "filter": "policy_updates"
}
```

### 3. AI Recommendation Generator
Command:

```powershell
python explain_drift_with_gemini.py
```

Result:

```text
[1/3] USER_ADDED_WITH_POLICIES principal=new_test
[2/3] USER_ADDED_WITH_POLICIES principal=test
[3/3] USER_ADDED_WITH_POLICIES principal=web_test
[OK] Wrote: D:\test_work\project_test\drift_recommendations.json
```

Recommendation sample:
- `new_test`: severity `LOW`
- `test`: severity `CRITICAL`
- `web_test`: severity `CRITICAL`

### 4. Bandit
Command:

```powershell
bandit -r .
```

Result summary:

```text
Total issues:
- High: 1
- Low: 14
```

Main finding:
- `dashboard_app.py` runs Flask with `debug=True`, which Bandit flags as a high-severity issue.

Other findings:
- Use of `subprocess` in watcher/dashboard scripts
- `assert` usage inside test files

### 5. pip-audit
Command:

```powershell
pip-audit -r requirements.txt
```

Result:

```text
flask 3.1.1   CVE-2026-27205   Fix: 3.1.3
Found 1 known vulnerability in 1 package
```

### 6. Semgrep
Command attempted:

```powershell
python -m pip install semgrep
```

Result:
- Could not run in this environment because Semgrep does not support native Windows here.

### 7. Gitleaks
Command attempted:

```powershell
Get-Command gitleaks
```

Result:
- `gitleaks` is not installed in the current environment.

## Sample Artifacts

Files that can be shown to the grader:
- [TESTING_PLAN.md](d:\test_work\project_test\TESTING_PLAN.md)
- [TEST_RESULTS.md](d:\test_work\project_test\TEST_RESULTS.md)
- [drift_report.json](d:\test_work\project_test\drift_report.json)
- [drift_recommendations.json](d:\test_work\project_test\drift_recommendations.json)
- [tests/test_project_smoke.py](d:\test_work\project_test\tests\test_project_smoke.py)

## Conclusion
- Functional smoke testing passed.
- AI output generation worked and produced recommendation results.
- Security review found issues that should be reported:
  - Flask should be upgraded from `3.1.1` to `3.1.3`
  - `debug=True` should not be used outside development
- Two tools were not fully runnable in this Windows environment: `semgrep` and `gitleaks`
