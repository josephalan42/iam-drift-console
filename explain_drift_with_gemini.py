import json
import os
import hashlib
from typing import Any, Dict, List

from google import genai


PROJECT_DIR = r"D:\test_work\project_test"
DRIFT_PATH = os.path.join(PROJECT_DIR, "drift_report.json")
OUT_PATH = os.path.join(PROJECT_DIR, "drift_recommendations.json")


HIGH_RISK_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

PRIV_ESC_ACTION_HINTS = {
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
}


def collect_actions(policy_doc: Any) -> List[str]:
    actions: List[str] = []
    if not isinstance(policy_doc, dict):
        return actions
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if not isinstance(s, dict):
            continue
        for key in ("Action", "NotAction"):
            val = s.get(key)
            if isinstance(val, str):
                actions.append(val)
            elif isinstance(val, list):
                actions.extend([x for x in val if isinstance(x, str)])
    return actions


def collect_resources(policy_doc: Any) -> List[str]:
    resources: List[str] = []
    if not isinstance(policy_doc, dict):
        return resources
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if not isinstance(s, dict):
            continue
        for key in ("Resource", "NotResource"):
            val = s.get(key)
            if isinstance(val, str):
                resources.append(val)
            elif isinstance(val, list):
                resources.extend([x for x in val if isinstance(x, str)])
    return resources


def extract_policy_entries(change: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    seen = set()

    def add_entry(policy_name: Any, policy_arn: Any, policy_doc: Any) -> None:
        if not isinstance(policy_doc, dict) and not policy_name and not policy_arn:
            return
        name = policy_name if isinstance(policy_name, str) else ""
        arn = policy_arn if isinstance(policy_arn, str) else ""
        doc = policy_doc if isinstance(policy_doc, dict) else {}
        sig = hashlib.sha256(json.dumps({"n": name, "a": arn, "d": doc}, sort_keys=True).encode("utf-8")).hexdigest()
        if sig in seen:
            return
        seen.add(sig)
        entries.append(
            {
                "policy_name": name or None,
                "policy_arn": arn or None,
                "policy_json": doc if doc else None,
            }
        )

    add_entry(change.get("policy_name"), change.get("policy_arn"), change.get("policy_json"))
    for list_key in ("added_inline_policies", "added_policies", "effective_added_policies", "policies"):
        for p in (change.get(list_key, []) or []):
            if not isinstance(p, dict):
                continue
            add_entry(p.get("policy_name"), p.get("policy_arn"), p.get("policy_json") or p.get("current_doc"))

    # Fallback source for events where we only have names/arns in summary.
    ps = change.get("policy_summary", {}) or {}
    if isinstance(ps, dict):
        for pname in (ps.get("user_inline_policy_names", []) or []):
            add_entry(pname, None, None)
        for arn in (ps.get("user_attached_policy_arns", []) or []):
            add_entry(None, arn, None)
        for arn in (ps.get("resolved_policy_arns", []) or []):
            add_entry(None, arn, None)
        for _, arns in (ps.get("group_attached_policy_arns", {}) or {}).items():
            for arn in (arns or []):
                add_entry(None, arn, None)
        for _, names in (ps.get("group_inline_policy_names", {}) or {}).items():
            for pname in (names or []):
                add_entry(pname, None, None)

    return entries


def compute_risk_flags(change: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    added_arns = set()
    for arn in (change.get("added_policy_arns", []) or []):
        if isinstance(arn, str) and arn:
            added_arns.add(arn)
    if isinstance(change.get("policy_arn"), str) and change.get("policy_arn"):
        added_arns.add(change["policy_arn"])
    for list_key in ("added_policies", "effective_added_policies"):
        for p in (change.get(list_key, []) or []):
            if isinstance(p, dict):
                arn = p.get("policy_arn")
                if isinstance(arn, str) and arn:
                    added_arns.add(arn)

    for arn in sorted(added_arns):
        flags.append(f"MANAGED_POLICY_ADDED:{arn}")
        if arn in HIGH_RISK_MANAGED_POLICIES:
            flags.append(f"HIGH_RISK_MANAGED_POLICY_ADDED:{arn}")

    policy_docs: List[Any] = []
    if change.get("policy_json"):
        policy_docs.append(change.get("policy_json"))
    for list_key in ("policies", "added_inline_policies", "added_policies", "effective_added_policies"):
        for p in (change.get(list_key, []) or []):
            if isinstance(p, dict):
                policy_docs.append(p.get("policy_json"))
                policy_docs.append(p.get("current_doc"))

    for doc in policy_docs:
        if not isinstance(doc, dict):
            continue
        actions = collect_actions(doc)
        resources = collect_resources(doc)

        for a in actions:
            action = a.strip()
            if action == "*":
                flags.append("WILDCARD_ACTION_STAR")
            elif action.endswith(":*"):
                flags.append(f"WILDCARD_ACTION_SERVICE:{action}")
            if action in PRIV_ESC_ACTION_HINTS:
                flags.append(f"SENSITIVE_ACTION_PRESENT:{action}")
            if action.lower() == "iam:*":
                flags.append("SENSITIVE_SERVICE_WILDCARD:IAM")

        for r in resources:
            resource = r.strip()
            if resource == "*":
                flags.append("WILDCARD_RESOURCE_STAR")
            elif resource.endswith(":*"):
                flags.append(f"WILDCARD_RESOURCE_SUFFIX:{resource}")

    if change.get("type") == "USER_GROUP_MEMBERSHIP_CHANGED" and change.get("added_groups"):
        flags.append("GROUP_MEMBERSHIP_ADDED")
    if isinstance(change.get("event_name"), str) and change.get("event_name"):
        flags.append(f"POLICY_EVENT:{change['event_name']}")

    return sorted(set(flags))


SYSTEM_INSTRUCTIONS = (
    "You are an IAM security analyst.\n"
    "Given one drift item, provide actionable recommendations.\n"
    "Rules:\n"
    "- Use only provided fields.\n"
    "- Keep recommendations concrete and short.\n"
    "- Recommendations must be policy-specific and service-specific.\n"
    "- Do not reuse the same generic advice across different services.\n"
    "- For each policy, mention likely affected AWS service areas.\n"
    "- Prefer least privilege.\n"
    "- If wildcard permissions exist, prioritize immediate containment.\n"
    "- Output valid JSON only matching schema.\n"
)


def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"[ERROR] Missing file: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def fallback_recommendation(change: Dict[str, Any], risk_flags: List[str]) -> Dict[str, Any]:
    severity = derive_severity_from_flags(risk_flags)
    variant = recommendation_variant(change)

    return {
        "severity": severity,
        "summary": variant["summary"],
        "possible_impact": impact_from_severity(severity),
        "policy_impact_analysis": fallback_policy_impact_analysis(change),
        "recommended_actions": variant["recommended_actions"],
        "rollback_steps": variant["rollback_steps"],
        "verification_steps": variant["verification_steps"],
        "confidence": "MEDIUM",
    }


def severity_rank(severity: str) -> int:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get((severity or "").upper(), 2)


def derive_severity_from_flags(risk_flags: List[str]) -> str:
    flags = set(risk_flags or [])
    if any(
        f.startswith("HIGH_RISK_MANAGED_POLICY_ADDED:")
        or f == "WILDCARD_ACTION_STAR"
        or f == "SENSITIVE_SERVICE_WILDCARD:IAM"
        for f in flags
    ):
        return "CRITICAL"
    if any(
        f.startswith("WILDCARD_ACTION_SERVICE:")
        or f.startswith("SENSITIVE_ACTION_PRESENT:")
        or f.startswith("MANAGED_POLICY_ADDED:")
        for f in flags
    ):
        return "HIGH"
    if flags:
        return "MEDIUM"
    return "LOW"


def impact_from_severity(severity: str) -> List[str]:
    sev = (severity or "MEDIUM").upper()
    if sev == "CRITICAL":
        return [
            "Potential full account compromise or privilege escalation.",
            "Sensitive data exposure and destructive actions may occur quickly.",
            "Compliance and incident-response impact is likely immediate.",
        ]
    if sev == "HIGH":
        return [
            "Expanded unauthorized access to key services or resources.",
            "Increased probability of lateral movement and policy abuse.",
        ]
    if sev == "MEDIUM":
        return [
            "Permission scope drift may enable unintended operations.",
            "Operational risk increases if additional weak changes are introduced.",
        ]
    return [
        "Limited immediate impact, but change should still be reviewed and approved.",
    ]


def recommendation_variant(change: Dict[str, Any]) -> Dict[str, List[str] | str]:
    principal = change.get("user") or change.get("principal") or "this principal"
    change_type = str(change.get("type", "UNKNOWN"))
    seed_src = f"{principal}|{change_type}|{json.dumps(change, sort_keys=True, default=str)}"
    seed = int(hashlib.sha256(seed_src.encode("utf-8")).hexdigest()[:8], 16)

    summaries = [
        f"Review {change_type} for {principal}; the access pattern changed and should be confirmed against expected IAM design.",
        f"{principal} now shows drift under {change_type}; confirm the permissions match an approved business need.",
        f"The drift item {change_type} changed access for {principal}; validate it before the scope spreads further.",
    ]
    action_sets = [
        [
            "Confirm who requested the change and whether it was formally approved.",
            "Trim the permission set back to least privilege for the affected AWS services.",
            "Record an owner and expiration date if temporary access is required.",
        ],
        [
            "Verify the policy change against the intended ticket or change record.",
            "Remove wildcard or unnecessary permissions before promoting the change.",
            "Assign clear ownership so future drift can be reviewed quickly.",
        ],
        [
            "Check that the principal still needs every added permission.",
            "Reduce the scope to exact actions and resources instead of broad access.",
            "Document why the change exists and when it should be revisited.",
        ],
    ]
    rollback_sets = [
        [
            "Detach the newly added managed policies or delete the inline statements that introduced the drift.",
            "Restore the last approved IAM baseline for the affected principal.",
        ],
        [
            "Revert the principal to the previous approved policy set.",
            "Remove any policy versions or attachments added during the drift event.",
        ],
        [
            "Back out the new permissions and re-apply the known good baseline.",
            "Re-check group or user attachments to confirm the rollback took effect.",
        ],
    ]
    verification_sets = [
        [
            "Re-run the drift detector and confirm the change no longer appears.",
            "Test the principal and verify only approved actions still succeed.",
        ],
        [
            "Refresh the dashboard data and confirm the policy warning count drops as expected.",
            "Validate that the principal can access only the intended AWS resources.",
        ],
        [
            "Run drift detection again to verify the environment returned to baseline.",
            "Confirm no extra managed or inline policies remain attached.",
        ],
    ]

    index = seed % len(summaries)
    return {
        "summary": summaries[index],
        "recommended_actions": action_sets[index],
        "rollback_steps": rollback_sets[index],
        "verification_steps": verification_sets[index],
    }


def fallback_policy_impact_analysis(change: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for entry in extract_policy_entries(change):
        doc = entry.get("policy_json") if isinstance(entry.get("policy_json"), dict) else {}
        actions = collect_actions(doc)
        resources = collect_resources(doc)
        services = sorted(set(a.split(":")[0] for a in actions if isinstance(a, str) and ":" in a))
        risky_actions = sorted([a for a in actions if a in PRIV_ESC_ACTION_HINTS or a.lower() == "iam:*"])
        has_star_action = any((isinstance(a, str) and (a.strip() == "*" or a.strip().endswith(":*"))) for a in actions)
        has_star_resource = any((isinstance(r, str) and r.strip() == "*") for r in resources)

        summary_parts = []
        if services:
            summary_parts.append(f"Grants access across service(s): {', '.join(services)}.")
        if has_star_action:
            summary_parts.append("Includes wildcard action scope.")
        if has_star_resource:
            summary_parts.append("Applies to all resources.")
        summary = " ".join(summary_parts) or "Policy permissions should be reviewed for least privilege."

        effects = []
        if has_star_action:
            effects.append("May allow broad operations including unintended administrative actions.")
        if has_star_resource:
            effects.append("Could affect production resources account-wide if misused.")
        if any(a.lower() == "iam:*" for a in actions if isinstance(a, str)):
            effects.append("May enable identity and permission tampering in the environment.")
        if not effects:
            effects.append("Could expand operational access beyond intended scope.")

        blast_radius = "LOW"
        if has_star_action and has_star_resource:
            blast_radius = "CRITICAL"
        elif has_star_action or has_star_resource:
            blast_radius = "HIGH"
        elif services:
            blast_radius = "MEDIUM"

        abuse_paths: List[str] = []
        if any(a.lower() == "iam:*" for a in actions if isinstance(a, str)):
            abuse_paths.append("Privilege escalation by creating/modifying IAM identities and policies.")
        if "iam:PassRole" in actions:
            abuse_paths.append("PassRole abuse to execute workloads with higher privileges.")
        if "sts:AssumeRole" in actions:
            abuse_paths.append("Cross-role pivot into broader access paths.")
        if "kms:Decrypt" in actions:
            abuse_paths.append("Unauthorized decryption of protected secrets and data.")
        if "secretsmanager:GetSecretValue" in actions:
            abuse_paths.append("Direct credential exfiltration from Secrets Manager.")
        if not abuse_paths and (has_star_action or has_star_resource):
            abuse_paths.append("Broad wildcard scope can be abused for lateral movement.")

        targeted_mitigations: List[str] = []
        if services:
            targeted_mitigations.append(f"Limit service scope to required APIs only: {', '.join(services)}.")
        if has_star_action:
            targeted_mitigations.append("Replace wildcard actions with explicit allow-lists.")
        if has_star_resource:
            targeted_mitigations.append("Replace Resource '*' with specific ARNs or strict tag conditions.")
        if any(a.lower() == "iam:*" for a in actions if isinstance(a, str)):
            targeted_mitigations.append("Apply permissions boundary/SCP guardrails to block IAM escalation operations.")
        if not targeted_mitigations:
            targeted_mitigations.append("Restrict policy to least privilege and document approved use-case.")

        out.append(
            {
                "policy_name": entry.get("policy_name"),
                "policy_arn": entry.get("policy_arn"),
                "policy_summary": summary,
                "affected_services": services,
                "risky_actions": risky_actions,
                "blast_radius": blast_radius,
                "abuse_paths": abuse_paths,
                "possible_environment_effects": effects,
                "targeted_mitigations": targeted_mitigations,
            }
        )
    return out


def derive_policy_context(change: Dict[str, Any]) -> Dict[str, Any]:
    services = set()
    actions = set()
    resources = set()
    sensitive_actions = set()
    has_action_star = False
    has_resource_star = False
    managed_policy_arns = []

    for f in compute_risk_flags(change):
        if f.startswith("MANAGED_POLICY_ADDED:"):
            managed_policy_arns.append(f.split(":", 1)[1])

    for entry in extract_policy_entries(change):
        doc = entry.get("policy_json") if isinstance(entry.get("policy_json"), dict) else {}
        for a in collect_actions(doc):
            if not isinstance(a, str):
                continue
            act = a.strip()
            actions.add(act)
            if ":" in act:
                services.add(act.split(":", 1)[0].lower())
            if act == "*":
                has_action_star = True
            if act.endswith(":*"):
                has_action_star = True
            if act in PRIV_ESC_ACTION_HINTS:
                sensitive_actions.add(act)
        for r in collect_resources(doc):
            if not isinstance(r, str):
                continue
            res = r.strip()
            resources.add(res)
            if res == "*":
                has_resource_star = True

    return {
        "services": sorted(services),
        "actions": sorted(actions),
        "resources": sorted(resources),
        "sensitive_actions": sorted(sensitive_actions),
        "has_action_star": has_action_star,
        "has_resource_star": has_resource_star,
        "managed_policy_arns": sorted(set(managed_policy_arns)),
    }


def service_specific_action_templates(policy_ctx: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    services = set(policy_ctx.get("services", []))
    sensitive = set(policy_ctx.get("sensitive_actions", []))

    if "iam" in services:
        out.append("Restrict IAM permissions to explicit actions (for example iam:Get*, iam:List*) and remove iam:*.")
        out.append("Apply a permissions boundary to the principal to block privilege escalation paths.")
    if "ec2" in services:
        out.append("Scope EC2 actions to approved instance, volume, and network resource ARNs or tags.")
    if "s3" in services:
        out.append("Limit S3 access to required bucket ARN prefixes and block account-wide s3:* patterns.")
    if "lambda" in services:
        out.append("Restrict Lambda actions to required functions and disallow wildcard invoke/update permissions.")
    if "rds" in services:
        out.append("Constrain RDS actions to approved DB instance/cluster ARNs and remove broad administrative actions.")
    if "kms" in services or "kms:Decrypt" in sensitive:
        out.append("Constrain KMS decrypt permissions with key ARN allow-list and encryption context conditions.")
    if "secretsmanager" in services or "secretsmanager:GetSecretValue" in sensitive:
        out.append("Scope Secrets Manager reads to approved secret ARNs and enforce resource policy checks.")

    if policy_ctx.get("has_action_star"):
        out.append("Replace wildcard action grants with minimal action allow-lists per service.")
    if policy_ctx.get("has_resource_star"):
        out.append("Replace Resource '*' with exact ARNs or tag-based conditions.")
    return out


def customize_fallback_recommendation(base: Dict[str, Any], change: Dict[str, Any], risk_flags: List[str]) -> Dict[str, Any]:
    out = dict(base)
    policy_ctx = derive_policy_context(change)
    extra_actions = service_specific_action_templates(policy_ctx)
    rec_actions = list(out.get("recommended_actions", []))
    for act in extra_actions:
        if act not in rec_actions:
            rec_actions.append(act)
    out["recommended_actions"] = rec_actions

    impacts = list(out.get("possible_impact", []))
    if policy_ctx.get("has_action_star"):
        impacts.append("Wildcard actions can be abused for rapid privilege expansion.")
    if policy_ctx.get("has_resource_star"):
        impacts.append("Resource-wide scope can affect production assets across environments.")
    if policy_ctx.get("sensitive_actions"):
        impacts.append("Sensitive IAM/KMS/Secrets operations increase credential and data exposure risk.")
    out["possible_impact"] = sorted(set(impacts))
    out["risk_context"] = policy_ctx
    return out


def normalize_ai_recommendation(ai: Dict[str, Any], risk_flags: List[str], change: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(ai) if isinstance(ai, dict) else {}
    baseline = derive_severity_from_flags(risk_flags)
    ai_sev = str(out.get("severity", "MEDIUM")).upper()
    chosen = ai_sev if ai_sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"
    if severity_rank(chosen) < severity_rank(baseline):
        chosen = baseline
    out["severity"] = chosen

    if not isinstance(out.get("possible_impact"), list) or not out.get("possible_impact"):
        out["possible_impact"] = impact_from_severity(chosen)
    if not isinstance(out.get("policy_impact_analysis"), list) or not out.get("policy_impact_analysis"):
        out["policy_impact_analysis"] = fallback_policy_impact_analysis(change)
    else:
        # Enforce structured, policy-specific shape even when model omits fields.
        fallback_items = fallback_policy_impact_analysis(change)
        by_key = {}
        for item in fallback_items:
            key = (item.get("policy_name"), item.get("policy_arn"))
            by_key[key] = item
        normalized_items = []
        for item in out.get("policy_impact_analysis", []):
            if not isinstance(item, dict):
                continue
            key = (item.get("policy_name"), item.get("policy_arn"))
            fb = by_key.get(key, {})
            merged = dict(fb)
            merged.update(item)
            for required in ("affected_services", "risky_actions", "abuse_paths", "possible_environment_effects", "targeted_mitigations"):
                if not isinstance(merged.get(required), list):
                    merged[required] = fb.get(required, [])
            if not isinstance(merged.get("blast_radius"), str):
                merged["blast_radius"] = fb.get("blast_radius", "MEDIUM")
            if not isinstance(merged.get("policy_summary"), str):
                merged["policy_summary"] = fb.get("policy_summary", "Policy permissions should be reviewed for least privilege.")
            normalized_items.append(merged)
        out["policy_impact_analysis"] = normalized_items if normalized_items else fallback_items
    if not isinstance(out.get("recommended_actions"), list):
        out["recommended_actions"] = []
    if not isinstance(out.get("rollback_steps"), list):
        out["rollback_steps"] = []
    if not isinstance(out.get("verification_steps"), list):
        out["verification_steps"] = []
    if out.get("confidence") not in {"LOW", "MEDIUM", "HIGH"}:
        out["confidence"] = "MEDIUM"
    if not isinstance(out.get("summary"), str):
        out["summary"] = "Review this drift item and apply least-privilege remediation."
    policy_ctx = derive_policy_context(change)
    out["risk_context"] = policy_ctx

    # Ensure AI output contains at least a few service-specific recommendations when context exists.
    templates = service_specific_action_templates(policy_ctx)
    rec_actions = list(out.get("recommended_actions", []))
    for t in templates[:4]:
        if t not in rec_actions:
            rec_actions.append(t)
    out["recommended_actions"] = rec_actions
    return out


def gemini_recommend_change(client: genai.Client, change: Dict[str, Any]) -> Dict[str, Any]:
    risk_flags = compute_risk_flags(change)
    policy_entries = extract_policy_entries(change)
    policy_ctx = derive_policy_context(change)
    payload = {
        "drift_item": change,
        "policies_to_explain": policy_entries,
        "risk_context": policy_ctx,
        "risk_flags": risk_flags,
        "output_contract": {
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "summary": "string",
            "possible_impact": ["string"],
            "policy_impact_analysis": [
                {
                    "policy_name": "string|null",
                    "policy_arn": "string|null",
                    "policy_summary": "string",
                    "affected_services": ["string"],
                    "risky_actions": ["string"],
                    "blast_radius": "LOW|MEDIUM|HIGH|CRITICAL",
                    "abuse_paths": ["string"],
                    "possible_environment_effects": ["string"],
                    "targeted_mitigations": ["string"],
                }
            ],
            "recommended_actions": ["string"],
            "rollback_steps": ["string"],
            "verification_steps": ["string"],
            "confidence": "LOW|MEDIUM|HIGH",
        },
    }

    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=[json.dumps(payload)],
        config={
            "system_instruction": SYSTEM_INSTRUCTIONS,
            "response_mime_type": "application/json",
            "temperature": 0.2,
        },
    )
    if not getattr(resp, "text", None):
        raise RuntimeError("Empty response from Gemini.")
    return json.loads(resp.text)


def main() -> None:
    drift = load_json(DRIFT_PATH)
    changes = drift.get("changes", [])
    has_key = bool(os.getenv("GEMINI_API_KEY"))
    client = genai.Client() if has_key else None

    out: Dict[str, Any] = {
        "summary": drift.get("summary", {}),
        "trigger_event": drift.get("trigger_event", {}),
        "generator_mode": "gemini" if has_key else "fallback_only",
        "recommendations": [],
    }

    for idx, change in enumerate(changes, start=1):
        change_type = change.get("type")
        principal = change.get("user") or change.get("principal") or "unknown"
        print(f"[{idx}/{len(changes)}] {change_type} principal={principal}")
        risk_flags = compute_risk_flags(change)
        try:
            if client is None:
                raise RuntimeError("GEMINI_API_KEY not set in process environment.")
            ai = normalize_ai_recommendation(gemini_recommend_change(client, change), risk_flags, change)
        except Exception as e:
            ai = customize_fallback_recommendation(fallback_recommendation(change, risk_flags), change, risk_flags)
            ai["fallback_reason"] = str(e)

        out["recommendations"].append(
            {
                "change": change,
                "risk_flags": risk_flags,
                "advice": ai,
            }
        )

    save_json(OUT_PATH, out)
    print(f"[OK] Wrote: {OUT_PATH}")


if __name__ == "__main__":
    main()
