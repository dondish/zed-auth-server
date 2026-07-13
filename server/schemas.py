"""JSON response shapes — must match crates/cloud_api_types."""


def authenticated_user_json(user: dict) -> dict:
    """AuthenticatedUser (crates/cloud_api_types/src/cloud_api_types.rs)."""
    return {
        "id_v2": user["id"],
        "legacy_user_id": user["legacy_user_id"],
        "metrics_id": user["metrics_id"],
        "username": user["username"],
        "avatar_url": user["avatar_url"],
        "github_login": user["github_login"],
        "name": user["name"],
        "is_staff": user["is_staff"],
        # Set so the client never shows a terms-of-service gate.
        "accepted_tos_at": user["created_at"][:23] + "Z"
        if not user["created_at"].endswith("Z")
        else user["created_at"],
        "has_connected_to_collab_once": True,
    }


def internal_user_json(user: dict) -> dict:
    """internal_api::User (crates/cloud_api_types/src/internal_api.rs)."""
    return {
        "id": user["id"],
        "legacy_user_id": user["legacy_user_id"],
        "username": user["username"],
        "github_login": user["github_login"],
        "avatar_url": user["avatar_url"],
        "name": user["name"],
        "admin": user["is_staff"],
        "connected_once": True,
    }


def get_authenticated_user_response(user: dict) -> dict:
    """GetAuthenticatedUserResponse with a permissive free plan."""
    return {
        "user": authenticated_user_json(user),
        "feature_flags": [],
        "organizations": [],
        "default_organization_id": None,
        "plans_by_organization": {},
        "configuration_by_organization": {},
        "plan": {
            "plan_v3": "zed_free",
            "subscription_period": None,
            "usage": {"edit_predictions": {"used": 0, "limit": "unlimited"}},
            "trial_started_at": None,
            "is_account_too_young": False,
            "has_overdue_invoices": False,
        },
    }
