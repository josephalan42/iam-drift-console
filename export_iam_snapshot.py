# =========================
# FILE 1: export_iam_snapshot.py
# Purpose:
#   - Export CURRENT IAM users + user/group policies to JSON
#   - Includes resolved managed policy documents (recommended for AI explanations)
# Output:
#   current_snapshot.json (or baseline_snapshot.json if you set OUT_FILENAME)
# =========================

import boto3
import json
import os
import urllib.parse
from datetime import datetime, timezone
from botocore.exceptions import ClientError


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILENAME = "current_snapshot.json"   # change to "baseline_snapshot.json" when capturing baseline
OUT_PATH = os.path.join(PROJECT_DIR, OUT_FILENAME)


def ensure_dir_for_file(path: str) -> None:
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_policy_document(doc):
    """
    AWS sometimes returns policy docs URL-encoded.
    If doc is string: URL-decode and JSON parse.
    If dict: return as-is.
    """
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            decoded = urllib.parse.unquote(doc)
            return json.loads(decoded)
        except Exception:
            return doc
    return doc


def get_all_iam_users(iam_client):
    users = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page.get("Users", []))
    return users


def get_attached_user_policies(iam_client, username):
    policies = []
    paginator = iam_client.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy in page.get("AttachedPolicies", []):
            policies.append(
                {"PolicyName": policy.get("PolicyName"), "PolicyArn": policy.get("PolicyArn")}
            )
    return policies


def get_inline_user_policies(iam_client, username):
    policies = []
    paginator = iam_client.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy_name in page.get("PolicyNames", []):
            resp = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
            policies.append(
                {"PolicyName": policy_name, "PolicyDocument": decode_policy_document(resp.get("PolicyDocument"))}
            )
    return policies


def get_user_groups(iam_client, username):
    groups = []
    paginator = iam_client.get_paginator("list_groups_for_user")
    for page in paginator.paginate(UserName=username):
        groups.extend(page.get("Groups", []))
    return groups


def get_group_policies(iam_client, group_name):
    group_data = {"AttachedPolicies": [], "InlinePolicies": []}

    paginator = iam_client.get_paginator("list_attached_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        for policy in page.get("AttachedPolicies", []):
            group_data["AttachedPolicies"].append(
                {"PolicyName": policy.get("PolicyName"), "PolicyArn": policy.get("PolicyArn")}
            )

    paginator = iam_client.get_paginator("list_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        for policy_name in page.get("PolicyNames", []):
            resp = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
            group_data["InlinePolicies"].append(
                {"PolicyName": policy_name, "PolicyDocument": decode_policy_document(resp.get("PolicyDocument"))}
            )

    return group_data


def resolve_managed_policy_document(iam_client, policy_arn: str):
    """
    Resolve a managed policy ARN to its default version document.
    Returns dict including doc, or an Error field.
    """
    try:
        pol = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        default_ver = pol["DefaultVersionId"]
        ver = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_ver)["PolicyVersion"]
        doc = decode_policy_document(ver.get("Document"))
        return {
            "PolicyArn": policy_arn,
            "DefaultVersionId": default_ver,
            "PolicyDocument": doc,
            "RetrievedAt": utc_now_iso(),
        }
    except ClientError as e:
        return {"PolicyArn": policy_arn, "Error": str(e), "RetrievedAt": utc_now_iso()}


def enrich_with_managed_policy_docs(iam_client, user_info: dict):
    resolved = {}

    # user attached policies
    for p in user_info.get("AttachedManagedPolicies", []):
        arn = p.get("PolicyArn")
        if arn and arn not in resolved:
            resolved[arn] = resolve_managed_policy_document(iam_client, arn)

    # group attached policies
    for _, gdata in (user_info.get("Groups") or {}).items():
        for p in gdata.get("AttachedPolicies", []):
            arn = p.get("PolicyArn")
            if arn and arn not in resolved:
                resolved[arn] = resolve_managed_policy_document(iam_client, arn)

    user_info["ResolvedManagedPolicies"] = resolved
    return user_info


def main():
    iam_client = boto3.client("iam")

    output = {
        "_meta": {
            "generated_at_utc": utc_now_iso(),
            "generator": "iam_export_snapshot_v3",
            "includes_resolved_managed_policy_docs": True,
        },
        "users": {}
    }

    print("[*] Retrieving IAM users...")
    users = get_all_iam_users(iam_client)

    for user in users:
        username = user["UserName"]
        print(f"[+] Processing user: {username}")

        user_info = {
            "UserArn": user.get("Arn"),
            "CreateDate": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
            "AttachedManagedPolicies": [],
            "InlinePolicies": [],
            "Groups": {}
        }

        user_info["AttachedManagedPolicies"] = get_attached_user_policies(iam_client, username)
        user_info["InlinePolicies"] = get_inline_user_policies(iam_client, username)

        groups = get_user_groups(iam_client, username)
        for group in groups:
            group_name = group["GroupName"]
            print(f"    -> Processing group: {group_name}")
            user_info["Groups"][group_name] = get_group_policies(iam_client, group_name)

        user_info = enrich_with_managed_policy_docs(iam_client, user_info)

        output["users"][username] = user_info

    ensure_dir_for_file(OUT_PATH)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n[OK] Export completed: {OUT_PATH}")


if __name__ == "__main__":
    main()

