import gzip
import io
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


# ----------------------------
# CONFIG (EDIT THESE)
# ----------------------------

CLOUDTRAIL_BUCKET = os.environ.get("CLOUDTRAIL_BUCKET", "YOUR_CLOUDTRAIL_BUCKET")
CLOUDTRAIL_PREFIX = os.environ.get("CLOUDTRAIL_PREFIX", "AWSLogs/")  # set to your CloudTrail prefix
REGION = os.environ.get("AWS_REGION", "us-east-1")

PROJECT_DIR = r"D:\test_work\project_test"
CHECKPOINT_PATH = os.path.join(PROJECT_DIR, "checkpoint.json")
DRIFT_CONTEXT_PATH = os.path.join(PROJECT_DIR, "drift_context.json")

EXPORTER = os.path.join(PROJECT_DIR, "iam_export_snapshot.py")
DRIFT_DETECTOR = os.path.join(PROJECT_DIR, "iam_drift_detector.py")
# OPTIONAL: Gemini explainer
GEMINI_EXPLAINER = os.path.join(PROJECT_DIR, "explain_drift_with_gemini.py")
RUN_GEMINI_ON_CHANGE = os.environ.get("RUN_GEMINI_ON_CHANGE", "1").strip().lower() in ("1", "true", "yes")

POLL_SECONDS = 20


# IAM write-ish events you care about (add more as needed)
IAM_EVENT_NAMES = {
    "CreateUser",
    "DeleteUser",
    "UpdateUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "CreateGroup",
    "DeleteGroup",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
    "PutGroupPolicy",
    "DeleteGroupPolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "DeletePolicyVersion",
    "DeletePolicy",
    "TagPolicy",
    "UntagPolicy",
    "CreateRole",
    "DeleteRole",
    "UpdateAssumeRolePolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "PutUserPermissionsBoundary",
    "DeleteUserPermissionsBoundary",
    "PutRolePermissionsBoundary",
    "DeleteRolePermissionsBoundary",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
}


# ----------------------------
# S3 / checkpoint helpers
# ----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_checkpoint() -> Dict[str, Any]:
    if not os.path.exists(CHECKPOINT_PATH):
        return {"last_key": None, "last_modified": None}
    try:
        with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        # Reset bad checkpoint content instead of crashing the watcher.
        return {"last_key": None, "last_modified": None}


def save_checkpoint(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CHECKPOINT_PATH) or ".", exist_ok=True)
    with open(CHECKPOINT_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def save_drift_context(trigger_rec: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(DRIFT_CONTEXT_PATH) or ".", exist_ok=True)
    payload = {
        "trigger_event": {
            "event_name": trigger_rec.get("eventName"),
            "event_time": trigger_rec.get("eventTime"),
            "actor": (trigger_rec.get("userIdentity") or {}).get("arn", "unknown"),
            "event_source": trigger_rec.get("eventSource"),
            "request_parameters": trigger_rec.get("requestParameters"),
            "resources": trigger_rec.get("resources"),
        },
        "written_at_utc": utc_now_iso(),
    }
    with open(DRIFT_CONTEXT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def list_new_objects(
    s3_client,
    last_modified_iso: Optional[str],
    last_key: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Lists CloudTrail objects newer than checkpoint.
    We use LastModified + Key to avoid re-processing.
    """
    paginator = s3_client.get_paginator("list_objects_v2")
    objs = []
    last_dt = None
    if last_modified_iso:
        try:
            last_dt = datetime.fromisoformat(last_modified_iso.replace("Z", "+00:00"))
        except ValueError:
            last_dt = None

    for page in paginator.paginate(Bucket=CLOUDTRAIL_BUCKET, Prefix=CLOUDTRAIL_PREFIX):
        for obj in page.get("Contents", []):
            lm = obj["LastModified"]
            key = obj["Key"]

            # CloudTrail log files typically end with .json.gz
            if not key.endswith(".json.gz"):
                continue

            if last_dt is None:
                objs.append({"Key": key, "LastModified": lm})
                continue
            if lm > last_dt:
                objs.append({"Key": key, "LastModified": lm})
                continue
            # Handle objects sharing the same LastModified timestamp.
            if lm == last_dt and (last_key is None or key > last_key):
                objs.append({"Key": key, "LastModified": lm})

    objs.sort(key=lambda x: (x["LastModified"], x["Key"]))
    return objs


def get_cloudtrail_records_from_gz(s3_client, key: str) -> List[Dict[str, Any]]:
    resp = s3_client.get_object(Bucket=CLOUDTRAIL_BUCKET, Key=key)
    raw = resp["Body"].read()

    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
        data = json.loads(gz.read().decode("utf-8"))

    return data.get("Records", [])


# ----------------------------
# Detection logic
# ----------------------------

def is_iam_write_event(rec: Dict[str, Any]) -> bool:
    if rec.get("eventSource") != "iam.amazonaws.com":
        return False
    name = rec.get("eventName")
    return name in IAM_EVENT_NAMES


def trigger_pipeline(trigger_rec: Dict[str, Any]) -> None:
    """
    Runs your exporter + drift detector locally.
    """
    event_name = trigger_rec.get("eventName")
    actor = (trigger_rec.get("userIdentity") or {}).get("arn", "unknown")
    event_time = trigger_rec.get("eventTime", "unknown")

    print("\n====================================================")
    print("[ALERT] IAM CHANGE DETECTED (CloudTrail)")
    print(f"  time : {event_time}")
    print(f"  event: {event_name}")
    print(f"  actor: {actor}")
    print("  Running: exporter -> drift detector -> recommendations")
    print("====================================================\n")

    for required_file in (EXPORTER, DRIFT_DETECTOR):
        if not os.path.exists(required_file):
            raise FileNotFoundError(f"Required script not found: {required_file}")

    # Save trigger event context so drift report can include attach timestamps.
    save_drift_context(trigger_rec)

    # 1) Export current snapshot
    subprocess.check_call([sys.executable, EXPORTER])

    # 2) Run drift detector
    subprocess.check_call([sys.executable, DRIFT_DETECTOR])

    # 3) Run Gemini recommendation step if enabled and configured
    if RUN_GEMINI_ON_CHANGE:
        if os.path.exists(GEMINI_EXPLAINER):
            subprocess.check_call([sys.executable, GEMINI_EXPLAINER])
        else:
            print("[WARN] Skipping recommendations (missing explain_drift_with_gemini.py).")


# ----------------------------
# Main loop
# ----------------------------

def main():
    if CLOUDTRAIL_BUCKET == "YOUR_CLOUDTRAIL_BUCKET":
        raise RuntimeError("Set CLOUDTRAIL_BUCKET env var or edit the script.")

    s3_client = boto3.client("s3", region_name=REGION)
    state = load_checkpoint()

    print("[OK] Local IAM change watcher started")
    print("  CloudTrail bucket:", CLOUDTRAIL_BUCKET)
    print("  CloudTrail prefix:", CLOUDTRAIL_PREFIX)
    print("  Project dir      :", PROJECT_DIR)
    print("  Poll seconds     :", POLL_SECONDS)
    print("  Started at       :", utc_now_iso())
    print()

    while True:
        try:
            new_objs = list_new_objects(
                s3_client,
                state.get("last_modified"),
                state.get("last_key"),
            )
            if not new_objs:
                time.sleep(POLL_SECONDS)
                continue

            for obj in new_objs:
                key = obj["Key"]
                lm = obj["LastModified"]

                records = get_cloudtrail_records_from_gz(s3_client, key)
                for rec in records:
                    if is_iam_write_event(rec):
                        trigger_pipeline(rec)

                # Advance checkpoint after processing each object.
                state["last_key"] = key
                state["last_modified"] = lm.isoformat()
                save_checkpoint(state)

        except ClientError as e:
            print("AWS error:", str(e), file=sys.stderr)
            time.sleep(POLL_SECONDS)
        except subprocess.CalledProcessError as e:
            print("[ERROR] Pipeline failed:", str(e), file=sys.stderr)
            time.sleep(POLL_SECONDS)
        except FileNotFoundError as e:
            print("[ERROR]", str(e), file=sys.stderr)
            time.sleep(POLL_SECONDS)
        except Exception as e:
            print("Unexpected error:", str(e), file=sys.stderr)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
