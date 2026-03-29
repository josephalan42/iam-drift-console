import iam_drift_detector as detector
import explain_drift_with_gemini as recommender
import dashboard_app
from dashboard_app import app


def test_normalize_policy_doc_ignores_statement_order():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"},
        ],
    }
    reordered = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetObject"], "Resource": "*"},
        ],
    }

    assert detector.normalize_policy_doc(policy) == detector.normalize_policy_doc(reordered)


def test_compute_risk_flags_marks_admin_policy_as_high_risk():
    change = {
        "type": "USER_ATTACHED_MANAGED_POLICY_CHANGE",
        "user": "alice",
        "added_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
    }

    flags = recommender.compute_risk_flags(change)

    assert "MANAGED_POLICY_ADDED:arn:aws:iam::aws:policy/AdministratorAccess" in flags
    assert "HIGH_RISK_MANAGED_POLICY_ADDED:arn:aws:iam::aws:policy/AdministratorAccess" in flags


def test_api_data_returns_summary_payload():
    client = app.test_client()

    response = client.get("/api/data")

    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert "summary" in payload
    assert "changes" in payload
    assert "recommendations" in payload


def test_policy_change_count_counts_nested_policy_lists():
    changes = [
        {
            "type": "USER_ADDED_WITH_POLICIES",
            "added_inline_policies": [{}, {}],
            "effective_added_policies": [{}],
        },
        {
            "type": "USER_INLINE_POLICY_MODIFIED",
            "policies": [{}, {}, {}],
        },
        {
            "type": "TRIGGER_POLICY_EVENT",
            "policy_name": "sample",
        },
    ]

    assert dashboard_app._count_policy_changes(changes) == 7


def test_fallback_recommendations_vary_by_change_identity():
    change_a = {"type": "USER_ADDED_WITH_POLICIES", "user": "alice"}
    change_b = {"type": "USER_ADDED_WITH_POLICIES", "user": "bob"}

    rec_a = recommender.fallback_recommendation(change_a, [])
    rec_b = recommender.fallback_recommendation(change_b, [])

    assert rec_a["summary"] != rec_b["summary"] or rec_a["recommended_actions"] != rec_b["recommended_actions"]


def test_build_search_text_includes_nested_policy_names():
    item = {
        "type": "USER_ADDED_WITH_POLICIES",
        "user": "test",
        "added_inline_policies": [
            {"policy_name": "test_lambda", "policy_json": {"Statement": [{"Action": ["lambda:*"]}]}}
        ],
    }

    text = dashboard_app.build_search_text(item)

    assert "test_lambda" in text
    assert "lambda:*" in text


def test_view_model_recommendations_include_search_text():
    vm = dashboard_app.build_view_model()

    assert vm["recommendations"]
    assert all("search_text" in rec for rec in vm["recommendations"])
