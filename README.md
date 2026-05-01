# IAM Drift Console

## BLUF
IAM Drift Console is a cloud security project that detects IAM drift in AWS, analyzes the security meaning of those changes, and presents the results through an AI-assisted dashboard workflow. The value of the project is that it does not stop at showing that something changed. It helps explain why the change matters, what services are affected, and what action should be taken next.

## Project Overview
This project was designed to improve how IAM changes are reviewed in AWS environments. In many cases, security teams can detect that a user, group, or policy changed, but they still need to spend extra time understanding whether that change introduces privilege escalation, excessive access, or other security risk.

IAM Drift Console addresses that problem by combining:

- IAM snapshot export
- deterministic drift detection
- AI-assisted recommendation generation
- a searchable dashboard for review

The result is a workflow that supports both technical analysis and faster decision-making.

## Why This Project Matters
Identity and access management is one of the highest-impact security layers in cloud environments. A single policy change can affect multiple services, expose sensitive data, or expand privilege unexpectedly. This project matters because it helps close the gap between raw detection and useful explanation.

Instead of asking a reviewer to interpret raw IAM differences manually, the system:

- identifies drift automatically
- classifies risky patterns
- generates structured recommendations
- presents the output in a form that is easier to understand and demonstrate

This makes the project useful not only as a coding exercise, but also as a practical example of how AI can support cybersecurity analysis when it is grounded in verified security data.

## Core Features

- Exports IAM snapshot data from AWS
- Compares a baseline snapshot to a current snapshot
- Detects user, group, and policy drift
- Computes risk signals such as wildcard access and sensitive IAM actions
- Generates AI-assisted recommendations with severity, impact, mitigations, rollback steps, and verification steps
- Displays findings in a dashboard with filtering, collapsible sections, and separate counts for user changes and policy changes
- Supports backend refresh so new IAM changes can be surfaced through the full workflow

## How the System Works

The system follows this sequence:

1. Export or load IAM snapshot data
2. Compare the baseline snapshot to the current snapshot
3. Generate a drift report based on detected changes
4. Pass the drift findings into the recommendation engine
5. Generate structured recommendations from the verified drift data
6. Display the findings in the dashboard for review

This design is important because the AI layer does not replace the detection logic. The security logic first determines what changed. The AI layer then helps explain the impact in a more useful format.

## Repository Structure

- `app.py` - Flask dashboard and API
- `export_iam_snapshot.py` - exports IAM snapshot data
- `detect_iam_drift.py` - compares snapshots and produces drift output
- `generate_drift_recommendations.py` - creates structured recommendations from drift findings
- `monitor_iam_changes.py` - optional watcher workflow for repeated IAM monitoring
- `templates/dashboard.html` - dashboard markup
- `static/dashboard.css` - dashboard styling
- `requirements.txt` - Python dependencies

## Demonstration of Work

This repository demonstrates a working integration of AI and cybersecurity components.

Examples of completed work include:

- a drift detector that identifies added users and policy-related changes
- a recommendation layer that produces severity ratings and service-specific guidance
- a dashboard that presents the findings in a more readable way
- backend refresh support so the interface can update data rather than only showing stale files
- repository cleanup to prevent generated IAM artifacts from being pushed publicly

During testing, the project successfully detected newly added IAM users and passed those findings into the recommendation layer. This confirmed that the export, drift detection, AI recommendation, and dashboard components all interact as one system.

## Technical Highlights

- Policy documents are normalized before comparison to reduce false positives caused by ordering differences
- Risk flags are generated from policy content, including wildcard permissions and sensitive IAM-related actions
- AI prompting is structured so the recommendation engine stays grounded in the provided drift data
- The recommendation system includes fallback behavior when no AI key is available
- The UI was refined with filtering, collapsible sections, and clearer separation of large text blocks

## Setup

### Requirements

- Python 3.13+
- AWS credentials configured locally if you want to export real IAM data
- Optional: `GEMINI_API_KEY` for AI-generated recommendations instead of fallback-only recommendations

### Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

## How To Run

### 1. Export a current snapshot

```powershell
python export_iam_snapshot.py
```

### 2. Generate a drift report

```powershell
python detect_iam_drift.py
```

### 3. Generate recommendations

```powershell
python generate_drift_recommendations.py
```

### 4. Start the dashboard

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Security and Privacy Notes

Generated local files such as snapshots, drift reports, recommendation outputs, and watcher state are intentionally ignored by Git. This helps prevent environment-specific IAM data or local security artifacts from being uploaded to the public repository.

The public repository is intentionally limited to the runtime code, app assets, dependency file, and README.

## Final Outcome

IAM Drift Console demonstrates that AI can add value to cybersecurity when it is constrained by structure and attached to verified security findings. The project shows a working integration of IAM drift detection, AI-assisted explanation, and dashboard-based review, while also demonstrating improvements in testing, repository hygiene, and usability over time.
