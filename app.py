import json
import os
import subprocess
import sys
import threading
import hashlib
import atexit
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DRIFT_REPORT_PATH = os.path.join(PROJECT_DIR, "drift_report.json")
DRIFT_RECOMMENDATIONS_PATH = os.path.join(PROJECT_DIR, "drift_recommendations.json")
WATCHER_SCRIPT_PATH = os.path.join(PROJECT_DIR, "monitor_iam_changes.py")
WATCHER_LOG_PATH = os.path.join(PROJECT_DIR, "watcher_runtime.log")
ERROR_LOG_PATH = os.path.join(PROJECT_DIR, "error.logs")


app = Flask(__name__)
_watcher_process: subprocess.Popen | None = None
_watcher_lock = threading.Lock()
_watcher_log_file = None
_watcher_err_file = None


def load_json_safe(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def normalize_recommendations(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs = data.get("recommendations", [])
    if not isinstance(recs, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in recs:
        if isinstance(item, dict):
            out.append(item)
    return out


def _flatten_search_tokens(value: Any) -> List[str]:
    tokens: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            tokens.append(str(key))
            tokens.extend(_flatten_search_tokens(item))
    elif isinstance(value, list):
        for item in value:
            tokens.extend(_flatten_search_tokens(item))
    elif value is not None:
        tokens.append(str(value))
    return tokens


def build_search_text(value: Any) -> str:
    return " ".join(_flatten_search_tokens(value)).lower()


def ensure_log_files_exist() -> None:
    for path in (WATCHER_LOG_PATH, ERROR_LOG_PATH):
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if not os.path.exists(path):
                with open(path, "a", encoding="utf-8"):
                    pass
        except OSError:
            pass


def file_mtime(path: str) -> float:
    if not os.path.exists(path):
        return 0.0
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def compute_data_hash() -> str:
    raw = f"{file_mtime(DRIFT_REPORT_PATH)}|{file_mtime(DRIFT_RECOMMENDATIONS_PATH)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def ensure_watcher_running() -> bool:
    global _watcher_process, _watcher_log_file, _watcher_err_file
    with _watcher_lock:
        if _watcher_process and _watcher_process.poll() is None:
            return True

        bucket = os.environ.get("CLOUDTRAIL_BUCKET", "YOUR_CLOUDTRAIL_BUCKET")
        if bucket == "YOUR_CLOUDTRAIL_BUCKET":
            return False

        if not os.path.exists(WATCHER_SCRIPT_PATH):
            return False

        try:
            _watcher_log_file = open(WATCHER_LOG_PATH, "a", encoding="utf-8")
            _watcher_err_file = open(ERROR_LOG_PATH, "a", encoding="utf-8")
        except OSError:
            _watcher_log_file = None
            _watcher_err_file = None
            return False
        _watcher_process = subprocess.Popen(
            [sys.executable, WATCHER_SCRIPT_PATH],
            cwd=PROJECT_DIR,
            stdout=_watcher_log_file,
            stderr=_watcher_err_file,
        )
        return True


def stop_watcher() -> None:
    global _watcher_process, _watcher_log_file, _watcher_err_file
    with _watcher_lock:
        if _watcher_process and _watcher_process.poll() is None:
            _watcher_process.terminate()
        _watcher_process = None
        if _watcher_log_file:
            _watcher_log_file.close()
            _watcher_log_file = None
        if _watcher_err_file:
            _watcher_err_file.close()
            _watcher_err_file = None


atexit.register(stop_watcher)


def build_view_model() -> Dict[str, Any]:
    ensure_log_files_exist()
    watcher_running = ensure_watcher_running()
    report = load_json_safe(DRIFT_REPORT_PATH)
    recs_raw = load_json_safe(DRIFT_RECOMMENDATIONS_PATH)

    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    changes = report.get("changes", []) if isinstance(report.get("changes"), list) else []
    trigger_event = report.get("trigger_event", {}) if isinstance(report.get("trigger_event"), dict) else {}
    recommendations = normalize_recommendations(recs_raw)
    change_rows = [_with_search_text(change) for change in changes]
    recommendation_rows = [_with_search_text(rec) for rec in recommendations]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for rec in recommendation_rows:
        advice = rec.get("advice", {})
        if isinstance(advice, dict):
            sev = str(advice.get("severity", "")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

    return {
        "summary": {
            "added_users": summary.get("added_users", []),
            "removed_users": summary.get("removed_users", []),
            "num_changes": summary.get("num_changes", 0),
            "filter": summary.get("filter", "all"),
            "user_change_count": _count_user_changes(changes),
            "policy_change_count": _count_policy_changes(changes),
        },
        "trigger_event": trigger_event,
        "changes": change_rows,
        "recommendations": recommendation_rows,
        "severity_counts": severity_counts,
        "change_type_counts": _count_change_types(change_rows),
        "last_updated_utc": datetime.utcnow().isoformat() + "Z",
        "data_hash": compute_data_hash(),
        "watcher_running": watcher_running,
    }


def _with_search_text(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    out["search_text"] = build_search_text(item)
    return out


def _count_change_types(changes: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for c in changes:
        if not isinstance(c, dict):
            continue
        k = str(c.get("type", "UNKNOWN"))
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda x: x[0]))


def _count_user_changes(changes: List[Dict[str, Any]]) -> int:
    user_change_types = {
        "USER_ADDED_WITH_POLICIES",
        "USER_REMOVED_WITH_POLICIES",
        "USER_GROUP_MEMBERSHIP_CHANGED",
    }
    return sum(1 for change in changes if str(change.get("type", "")) in user_change_types)


def _count_policy_changes(changes: List[Dict[str, Any]]) -> int:
    total = 0
    for change in changes:
        if not isinstance(change, dict):
            continue

        for key in (
            "added_inline_policies",
            "effective_added_policies",
            "added_policies",
            "removed_policies",
            "policies",
        ):
            value = change.get(key)
            if isinstance(value, list):
                total += len(value)

        for key in ("added_policy_arns", "removed_policy_arns", "policy_names"):
            value = change.get(key)
            if isinstance(value, list):
                total += len(value)

        if change.get("policy_name") or change.get("policy_arn"):
            total += 1

    return total


@app.route("/")
def dashboard() -> str:
    vm = build_view_model()
    return render_template("dashboard.html", vm=vm)


@app.route("/api/data")
def api_data():
    return jsonify(build_view_model())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
