# =========================
# FILE 2: detect_iam_drift.py
# Purpose:
#   - Compare baseline_snapshot.json vs current_snapshot.json
#   - Output deterministic drift report: drift_report.json
# Notes:
#   - Handles new JSON structure: {"_meta":..., "users": {...}}
#   - Fails gracefully if baseline/current file missing
# =========================

import json
import hashlib
import os
from copy import deepcopy
from typing import Any, Dict, List


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_PATH = os.path.join(PROJECT_DIR, "baseline_snapshot.json")
CURRENT_PATH = os.path.join(PROJECT_DIR, "current_snapshot.json")
OUT_PATH = os.path.join(PROJECT_DIR, "drift_report.json")
CONTEXT_PATH = os.path.join(PROJECT_DIR, "event_context.json")
CHANGE_FILTER = os.environ.get("DRIFT_CHANGE_FILTER", "policy_updates").strip().lower()

POLICY_UPDATE_CHANGE_TYPES = {
    "TRIGGER_POLICY_EVENT",
    "USER_ADDED_WITH_POLICIES",
    "USER_REMOVED_WITH_POLICIES",
    "USER_ATTACHED_MANAGED_POLICY_CHANGE",
    "USER_EFFECTIVE_MANAGED_POLICY_CHANGE",
    "USER_INLINE_POLICY_ADDED",
    "USER_INLINE_POLICY_REMOVED",
    "USER_INLINE_POLICY_MODIFIED",
    "USER_RESOLVED_MANAGED_POLICY_MODIFIED",
    "GROUP_ATTACHED_MANAGED_POLICY_CHANGE",
    "GROUP_INLINE_POLICY_ADDED",
    "GROUP_INLINE_POLICY_REMOVED",
    "GROUP_INLINE_POLICY_MODIFIED",
}


def stable_hash(obj: Any) -> str:
    dumped = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def normalize_policy_doc(policy_doc: Any) -> Any:
    doc = deepcopy(policy_doc)
    if not isinstance(doc, dict):
        return doc

    stmts = doc.get("Statement")
    if stmts is None:
        return doc

    if isinstance(stmts, dict):
        stmts = [stmts]

    def norm_stmt(stmt: Dict[str, Any]) -> Dict[str, Any]:
        s = deepcopy(stmt)
        for key in ["Action", "NotAction", "Resource", "NotResource"]:
            if key in s:
                if isinstance(s[key], str):
                    s[key] = [s[key]]
                if isinstance(s[key], list):
                    s[key] = sorted(s[key])
        return s

    normalized = [norm_stmt(s) for s in stmts]
    normalized.sort(key=lambda x: stable_hash(x))
    doc["Statement"] = normalized
    return doc


def canonicalize_snapshot(users_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Input: users_snapshot == baseline_raw["users"] or current_raw["users"]
    """
    out = {}

    for username, u in users_snapshot.items():
        u2 = deepcopy(u)

        # Sort attached managed policies
        u2["AttachedManagedPolicies"] = sorted(
            u2.get("AttachedManagedPolicies", []) or [],
            key=lambda p: p.get("PolicyArn", "")
        )

        # Inline user policies: normalize + hash
        inlines = []
        for p in u2.get("InlinePolicies", []) or []:
            p2 = deepcopy(p)
            p2["PolicyDocument"] = normalize_policy_doc(p2.get("PolicyDocument"))
            p2["_hash"] = stable_hash(p2["PolicyDocument"])
            inlines.append(p2)

        inlines.sort(key=lambda x: (x.get("PolicyName", ""), x.get("_hash", "")))
        u2["InlinePolicies"] = inlines

        # Groups: sort groups and normalize group inline policies
        groups = u2.get("Groups", {}) or {}
        canon_groups = {}

        for gname in sorted(groups.keys()):
            g = deepcopy(groups[gname])

            g["AttachedPolicies"] = sorted(
                g.get("AttachedPolicies", []) or [],
                key=lambda p: p.get("PolicyArn", "")
            )

            ginlines = []
            for p in g.get("InlinePolicies", []) or []:
                p2 = deepcopy(p)
                p2["PolicyDocument"] = normalize_policy_doc(p2.get("PolicyDocument"))
                p2["_hash"] = stable_hash(p2["PolicyDocument"])
                ginlines.append(p2)

            ginlines.sort(key=lambda x: (x.get("PolicyName", ""), x.get("_hash", "")))
            g["InlinePolicies"] = ginlines

            canon_groups[gname] = g

        u2["Groups"] = canon_groups

        # Keep resolved managed policies map if present (useful later for AI enrichment)
        # Normalize documents and store a stable hash for drift diffing.
        resolved = deepcopy(u2.get("ResolvedManagedPolicies", {}) or {})
        canon_resolved: Dict[str, Dict[str, Any]] = {}
        for policy_arn in sorted(resolved.keys()):
            rp = deepcopy(resolved[policy_arn])
            rp_doc = normalize_policy_doc(rp.get("PolicyDocument"))
            rp["PolicyDocument"] = rp_doc
            rp["_hash"] = stable_hash(rp_doc)
            canon_resolved[policy_arn] = rp
        u2["ResolvedManagedPolicies"] = canon_resolved

        out[username] = u2

    return out


def diff_users(
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    current_generated_at_utc: str,
    trigger_event: Dict[str, Any],
) -> Dict[str, Any]:
    baseline_users = set(baseline.keys())
    current_users = set(current.keys())

    added_users = sorted(list(current_users - baseline_users))
    removed_users = sorted(list(baseline_users - current_users))
    common_users = sorted(list(baseline_users & current_users))

    changes: List[Dict[str, Any]] = []
    trigger_event_name = trigger_event.get("event_name")
    trigger_event_time = trigger_event.get("event_time")

    def change_context() -> Dict[str, Any]:
        return {
            "detected_at_utc": current_generated_at_utc,
            "trigger_event_name": trigger_event_name,
            "trigger_event_time": trigger_event_time,
        }

    def policy_set(attached_list: List[Dict[str, str]]) -> set:
        return set([p.get("PolicyArn") for p in (attached_list or []) if p.get("PolicyArn")])

    def effective_managed_policy_set(user_obj: Dict[str, Any]) -> set:
        out = set(policy_set(user_obj.get("AttachedManagedPolicies")))
        for gdata in (user_obj.get("Groups") or {}).values():
            out |= policy_set(gdata.get("AttachedPolicies"))
        return out

    def inline_map(inline_list: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        m = {}
        for p in inline_list or []:
            name = p.get("PolicyName", "")
            if name:
                m[name] = p
        return m

    def policy_name_map(user_obj: Dict[str, Any]) -> Dict[str, str]:
        names: Dict[str, str] = {}
        for p in user_obj.get("AttachedManagedPolicies", []) or []:
            arn = p.get("PolicyArn")
            if arn:
                names[arn] = p.get("PolicyName", "")
        for gdata in (user_obj.get("Groups") or {}).values():
            for p in gdata.get("AttachedPolicies", []) or []:
                arn = p.get("PolicyArn")
                if arn and arn not in names:
                    names[arn] = p.get("PolicyName", "")
        return names

    def policy_details_for_arns(user_obj: Dict[str, Any], policy_arns: List[str]) -> List[Dict[str, Any]]:
        name_map = policy_name_map(user_obj)
        resolved = user_obj.get("ResolvedManagedPolicies", {}) or {}
        details: List[Dict[str, Any]] = []
        for arn in sorted(policy_arns):
            rp = resolved.get(arn, {}) or {}
            details.append({
                "policy_arn": arn,
                "policy_name": name_map.get(arn, ""),
                "default_version_id": rp.get("DefaultVersionId"),
                "policy_json": rp.get("PolicyDocument"),
                "attach_event_name": trigger_event_name,
                "attached_at_utc": trigger_event_time,
                "detected_at_utc": current_generated_at_utc,
            })
        return details

    def inline_policy_details(inline_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        details: List[Dict[str, Any]] = []
        for p in inline_list or []:
            pname = p.get("PolicyName", "")
            if not pname:
                continue
            details.append({
                "policy_name": pname,
                "policy_json": p.get("PolicyDocument"),
                "attach_event_name": trigger_event_name,
                "attached_at_utc": trigger_event_time,
                "detected_at_utc": current_generated_at_utc,
            })
        details.sort(key=lambda x: x.get("policy_name", ""))
        return details

    def user_policy_summary(user_obj: Dict[str, Any]) -> Dict[str, Any]:
        user_attached = sorted(list(policy_set(user_obj.get("AttachedManagedPolicies"))))
        user_inline = sorted([p.get("PolicyName", "") for p in (user_obj.get("InlinePolicies") or []) if p.get("PolicyName")])
        group_names = sorted(list((user_obj.get("Groups") or {}).keys()))
        group_attached: Dict[str, List[str]] = {}
        group_inline: Dict[str, List[str]] = {}
        for gname in group_names:
            g = (user_obj.get("Groups") or {}).get(gname, {})
            group_attached[gname] = sorted(list(policy_set(g.get("AttachedPolicies"))))
            group_inline[gname] = sorted([p.get("PolicyName", "") for p in (g.get("InlinePolicies") or []) if p.get("PolicyName")])

        resolved = sorted(list((user_obj.get("ResolvedManagedPolicies") or {}).keys()))
        return {
            "user_attached_policy_arns": user_attached,
            "user_inline_policy_names": user_inline,
            "group_names": group_names,
            "group_attached_policy_arns": group_attached,
            "group_inline_policy_names": group_inline,
            "resolved_policy_arns": resolved,
        }

    for username in added_users:
        c_user = current[username]
        changes.append({
            "type": "USER_ADDED_WITH_POLICIES",
            "user": username,
            "policy_summary": user_policy_summary(c_user),
            "effective_added_policies": policy_details_for_arns(
                c_user,
                sorted(list(effective_managed_policy_set(c_user))),
            ),
            "added_inline_policies": inline_policy_details(c_user.get("InlinePolicies", []) or []),
            "context": change_context(),
        })

    for username in removed_users:
        changes.append({
            "type": "USER_REMOVED_WITH_POLICIES",
            "user": username,
            "policy_summary": user_policy_summary(baseline[username]),
            "context": change_context(),
        })

    for username in common_users:
        b = baseline[username]
        c = current[username]

        # 1) User attached managed policies (ARN set diff)
        b_att = policy_set(b.get("AttachedManagedPolicies"))
        c_att = policy_set(c.get("AttachedManagedPolicies"))

        added_att = sorted(list(c_att - b_att))
        removed_att = sorted(list(b_att - c_att))
        if added_att or removed_att:
            changes.append({
                "type": "USER_ATTACHED_MANAGED_POLICY_CHANGE",
                "user": username,
                "added_policy_arns": added_att,
                "removed_policy_arns": removed_att,
                "added_policies": policy_details_for_arns(c, added_att),
                "removed_policies": policy_details_for_arns(b, removed_att),
                "context": change_context(),
            })

        b_eff_att = effective_managed_policy_set(b)
        c_eff_att = effective_managed_policy_set(c)
        eff_added = sorted(list(c_eff_att - b_eff_att))
        eff_removed = sorted(list(b_eff_att - c_eff_att))
        if eff_added or eff_removed:
            changes.append({
                "type": "USER_EFFECTIVE_MANAGED_POLICY_CHANGE",
                "user": username,
                "added_policy_arns": eff_added,
                "removed_policy_arns": eff_removed,
                "added_policies": policy_details_for_arns(c, eff_added),
                "removed_policies": policy_details_for_arns(b, eff_removed),
                "context": change_context(),
            })

        # 2) User inline policies
        b_in = inline_map(b.get("InlinePolicies"))
        c_in = inline_map(c.get("InlinePolicies"))

        added_inline = sorted(list(set(c_in.keys()) - set(b_in.keys())))
        removed_inline = sorted(list(set(b_in.keys()) - set(c_in.keys())))
        common_inline = sorted(list(set(b_in.keys()) & set(c_in.keys())))

        if added_inline:
            changes.append({
                "type": "USER_INLINE_POLICY_ADDED",
                "user": username,
                "policy_names": added_inline,
                "policies": [
                    {
                        "policy_name": pname,
                        "current_hash": c_in[pname].get("_hash"),
                        "policy_json": c_in[pname].get("PolicyDocument"),
                        "attached_at_utc": trigger_event_time,
                        "detected_at_utc": current_generated_at_utc,
                    }
                    for pname in added_inline
                ],
                "context": change_context(),
            })
        if removed_inline:
            changes.append({
                "type": "USER_INLINE_POLICY_REMOVED",
                "user": username,
                "policy_names": removed_inline,
                "context": change_context(),
            })

        modified_inline = []
        for pname in common_inline:
            if b_in[pname].get("_hash") != c_in[pname].get("_hash"):
                modified_inline.append({
                    "policy_name": pname,
                    "baseline_hash": b_in[pname].get("_hash"),
                    "current_hash": c_in[pname].get("_hash"),
                    "baseline_doc": b_in[pname].get("PolicyDocument"),
                    "current_doc": c_in[pname].get("PolicyDocument")
                })
        if modified_inline:
            changes.append({
                "type": "USER_INLINE_POLICY_MODIFIED",
                "user": username,
                "policies": modified_inline,
                "context": change_context(),
            })

        # 3) Group membership changes
        b_groups = set((b.get("Groups") or {}).keys())
        c_groups = set((c.get("Groups") or {}).keys())

        added_groups = sorted(list(c_groups - b_groups))
        removed_groups = sorted(list(b_groups - c_groups))
        if added_groups or removed_groups:
            changes.append({
                "type": "USER_GROUP_MEMBERSHIP_CHANGED",
                "user": username,
                "added_groups": added_groups,
                "removed_groups": removed_groups,
                "context": change_context(),
            })

        # 4) Group policy diffs for common groups
        for gname in sorted(list(b_groups & c_groups)):
            bg = b["Groups"][gname]
            cg = c["Groups"][gname]

            bg_att = policy_set(bg.get("AttachedPolicies"))
            cg_att = policy_set(cg.get("AttachedPolicies"))
            g_added = sorted(list(cg_att - bg_att))
            g_removed = sorted(list(bg_att - cg_att))

            if g_added or g_removed:
                bg_name_map = {p.get("PolicyArn"): p.get("PolicyName", "") for p in (bg.get("AttachedPolicies") or []) if p.get("PolicyArn")}
                cg_name_map = {p.get("PolicyArn"): p.get("PolicyName", "") for p in (cg.get("AttachedPolicies") or []) if p.get("PolicyArn")}
                b_resolved = b.get("ResolvedManagedPolicies", {}) or {}
                c_resolved = c.get("ResolvedManagedPolicies", {}) or {}
                changes.append({
                    "type": "GROUP_ATTACHED_MANAGED_POLICY_CHANGE",
                    "user": username,
                    "group": gname,
                    "added_policy_arns": g_added,
                    "removed_policy_arns": g_removed,
                    "added_policies": [
                        {
                            "policy_arn": arn,
                            "policy_name": cg_name_map.get(arn, ""),
                            "default_version_id": (c_resolved.get(arn, {}) or {}).get("DefaultVersionId"),
                            "policy_json": (c_resolved.get(arn, {}) or {}).get("PolicyDocument"),
                            "attached_at_utc": trigger_event_time,
                            "detected_at_utc": current_generated_at_utc,
                        }
                        for arn in g_added
                    ],
                    "removed_policies": [
                        {
                            "policy_arn": arn,
                            "policy_name": bg_name_map.get(arn, ""),
                            "default_version_id": (b_resolved.get(arn, {}) or {}).get("DefaultVersionId"),
                            "policy_json": (b_resolved.get(arn, {}) or {}).get("PolicyDocument"),
                            "detected_at_utc": current_generated_at_utc,
                        }
                        for arn in g_removed
                    ],
                    "context": change_context(),
                })

            bg_in = inline_map(bg.get("InlinePolicies"))
            cg_in = inline_map(cg.get("InlinePolicies"))

            g_added_inline = sorted(list(set(cg_in.keys()) - set(bg_in.keys())))
            g_removed_inline = sorted(list(set(bg_in.keys()) - set(cg_in.keys())))
            g_common_inline = sorted(list(set(bg_in.keys()) & set(cg_in.keys())))

            if g_added_inline:
                changes.append({
                    "type": "GROUP_INLINE_POLICY_ADDED",
                    "user": username,
                    "group": gname,
                    "policy_names": g_added_inline,
                    "policies": [
                        {
                            "policy_name": pname,
                            "current_hash": cg_in[pname].get("_hash"),
                            "policy_json": cg_in[pname].get("PolicyDocument"),
                            "attached_at_utc": trigger_event_time,
                            "detected_at_utc": current_generated_at_utc,
                        }
                        for pname in g_added_inline
                    ],
                    "context": change_context(),
                })
            if g_removed_inline:
                changes.append({
                    "type": "GROUP_INLINE_POLICY_REMOVED",
                    "user": username,
                    "group": gname,
                    "policy_names": g_removed_inline,
                    "context": change_context(),
                })

            g_modified_inline = []
            for pname in g_common_inline:
                if bg_in[pname].get("_hash") != cg_in[pname].get("_hash"):
                    g_modified_inline.append({
                        "policy_name": pname,
                        "baseline_hash": bg_in[pname].get("_hash"),
                        "current_hash": cg_in[pname].get("_hash"),
                        "baseline_doc": bg_in[pname].get("PolicyDocument"),
                        "current_doc": cg_in[pname].get("PolicyDocument")
                    })

            if g_modified_inline:
                changes.append({
                    "type": "GROUP_INLINE_POLICY_MODIFIED",
                    "user": username,
                    "group": gname,
                    "policies": g_modified_inline,
                    "context": change_context(),
                })

        # 5) Resolved managed policy doc/version updates for user-attached policies
        b_resolved = b.get("ResolvedManagedPolicies", {}) or {}
        c_resolved = c.get("ResolvedManagedPolicies", {}) or {}
        common_attached_arns = sorted(list(b_eff_att & c_eff_att))
        resolved_modified = []
        for policy_arn in common_attached_arns:
            bp = b_resolved.get(policy_arn)
            cp = c_resolved.get(policy_arn)
            if not bp or not cp:
                continue
            baseline_hash = bp.get("_hash")
            current_hash = cp.get("_hash")
            baseline_version = bp.get("DefaultVersionId")
            current_version = cp.get("DefaultVersionId")
            if baseline_hash != current_hash or baseline_version != current_version:
                resolved_modified.append({
                    "policy_arn": policy_arn,
                    "baseline_default_version": baseline_version,
                    "current_default_version": current_version,
                    "baseline_hash": baseline_hash,
                    "current_hash": current_hash,
                    "baseline_doc": bp.get("PolicyDocument"),
                    "current_doc": cp.get("PolicyDocument"),
                })
        if resolved_modified:
            changes.append({
                "type": "USER_RESOLVED_MANAGED_POLICY_MODIFIED",
                "user": username,
                "policies": resolved_modified,
                "context": change_context(),
            })

    return {
        "summary": {
            "added_users": added_users,
            "removed_users": removed_users,
            "num_changes": len(changes)
        },
        "trigger_event": trigger_event,
        "changes": changes
    }


def parse_json_maybe(raw: Any) -> Any:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return raw


def build_trigger_policy_change(trigger_event: Dict[str, Any], detected_at_utc: str) -> Dict[str, Any]:
    if not isinstance(trigger_event, dict) or not trigger_event:
        return {}

    event_name = trigger_event.get("event_name")
    event_time = trigger_event.get("event_time")
    actor = trigger_event.get("actor")
    req = trigger_event.get("request_parameters") or {}

    policy_name = req.get("policyName")
    policy_arn = req.get("policyArn")
    policy_doc = parse_json_maybe(req.get("policyDocument"))
    principal = req.get("userName") or req.get("groupName") or req.get("roleName")

    if not any([policy_name, policy_arn, policy_doc]):
        return {}

    return {
        "type": "TRIGGER_POLICY_EVENT",
        "event_name": event_name,
        "actor": actor,
        "principal": principal,
        "policy_name": policy_name,
        "policy_arn": policy_arn,
        "policy_json": policy_doc,
        "attached_at_utc": event_time,
        "detected_at_utc": detected_at_utc,
    }


def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"\n[ERROR] File not found: {path}\n"
            f"Fix: confirm the file exists OR rename it correctly.\n"
            f"Tip: run `dir {PROJECT_DIR}` to verify filenames.\n"
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_optional_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def apply_change_filter(report: Dict[str, Any]) -> Dict[str, Any]:
    if CHANGE_FILTER in ("", "all"):
        return report
    if CHANGE_FILTER == "policy_updates":
        filtered_changes = [c for c in report.get("changes", []) if c.get("type") in POLICY_UPDATE_CHANGE_TYPES]
        out = deepcopy(report)
        out["changes"] = filtered_changes
        out["summary"]["num_changes"] = len(filtered_changes)
        out["summary"]["filter"] = "policy_updates"
        return out
    raise ValueError("Invalid DRIFT_CHANGE_FILTER. Use 'policy_updates' or 'all'.")


def main():
    print("Baseline path:", BASELINE_PATH, "| exists?", os.path.exists(BASELINE_PATH))
    print("Current path :", CURRENT_PATH, "| exists?", os.path.exists(CURRENT_PATH))

    baseline_raw = load_json(BASELINE_PATH)
    current_raw = load_json(CURRENT_PATH)
    context_raw = load_optional_json(CONTEXT_PATH)
    trigger_event = context_raw.get("trigger_event", {}) if isinstance(context_raw, dict) else {}
    current_generated_at_utc = ((current_raw.get("_meta") or {}).get("generated_at_utc")) or ""

    # [OK] IMPORTANT: use the "users" key (new exporter structure)
    baseline_users = baseline_raw.get("users", {})
    current_users = current_raw.get("users", {})

    baseline = canonicalize_snapshot(baseline_users)
    current = canonicalize_snapshot(current_users)

    report = diff_users(baseline, current, current_generated_at_utc, trigger_event)

    trigger_policy_change = build_trigger_policy_change(trigger_event, current_generated_at_utc)
    if trigger_policy_change:
        report["changes"].insert(0, trigger_policy_change)
        report["summary"]["num_changes"] = len(report["changes"])

    report = apply_change_filter(report)
    save_json(OUT_PATH, report)

    print(f"\n[OK] Drift report written to: {OUT_PATH}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()

