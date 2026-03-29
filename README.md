# IAM Drift Console

IAM Drift Console is a Python-based security project that detects IAM drift in AWS snapshots and turns those changes into readable, risk-focused recommendations. It combines drift detection, AI-assisted explanation, and a lightweight dashboard so users can move from raw IAM changes to actionable review faster.

## What This Project Does

- exports IAM snapshot data from AWS
- compares a baseline snapshot to a current snapshot
- detects user, group, and policy drift
- generates structured recommendations for risky changes
- displays findings in a searchable dashboard

## Project Structure

- `app.py`: Flask dashboard and API
- `export_iam_snapshot.py`: exports IAM snapshot data
- `detect_iam_drift.py`: compares snapshots and produces drift output
- `generate_drift_recommendations.py`: creates recommendation output from drift data
- `monitor_iam_changes.py`: optional watcher workflow for CloudTrail-driven updates
- `templates/dashboard.html`: dashboard markup
- `static/dashboard.css`: dashboard styling
- `tests/test_project_smoke.py`: smoke tests

## Requirements

- Python 3.13+
- AWS credentials configured locally if you want to export real IAM data
- optional: `GEMINI_API_KEY` if you want AI-generated recommendations instead of fallback-only recommendations

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## How To Run

1. Export a current snapshot:

```powershell
python export_iam_snapshot.py
```

2. Generate a drift report:

```powershell
python detect_iam_drift.py
```

3. Generate recommendations:

```powershell
python generate_drift_recommendations.py
```

4. Start the dashboard:

```powershell
python app.py
```

Then open `http://127.0.0.1:5000`.

## Testing

Run the smoke test suite with:

```powershell
python -m pytest -q
```

## Generated Local Files

The following files are generated locally during runs and are intentionally ignored by Git:

- `baseline_snapshot.json`
- `current_snapshot.json`
- `drift_report.json`
- `drift_recommendations.json`
- `event_context.json`
- `watcher_checkpoint.json`
- `error.logs`
- `watcher_runtime.log`

This helps prevent environment-specific or sensitive data from being committed accidentally.

## Notes

- The recommendation engine includes fallback behavior when no AI API key is available.
- The dashboard includes filtering, collapsible recommendation sections, and separate counts for user events and policy changes.
- This repository is intended for educational and project demonstration use.
