"""Coverage analysis: which users and apps are actually protected.

A user group or app counts as protected when at least one *enabled*
policy includes it and requires MFA, a block, or an authentication
strength. Break-glass accounts should be *excluded* from Conditional
Access policies so emergency access always works.
"""

import json


def load_config(path):
    """Load a coverage config JSON file.

    Format: {"break_glass_accounts": [...], "critical_apps": [...],
             "user_groups": [...]}
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("coverage config must be a JSON object")
    return data


def _is_enforced(policy):
    return str(policy.get("state", "")).lower() == "enabled"


def _requires_mfa_or_block(policy):
    grants = policy.get("grantControls") or {}
    controls = [str(c).lower() for c in grants.get("builtInControls") or []]
    return "mfa" in controls or "block" in controls \
        or bool(grants.get("authenticationStrength"))


def _includes(cond, key, value):
    included = cond.get(key) or []
    return "All" in included or value in included


def _protected(policies, kind, value):
    """True when an enabled MFA/block policy covers this user/app."""
    for policy in policies:
        if not _is_enforced(policy) or not _requires_mfa_or_block(policy):
            continue
        cond = policy.get("conditions") or {}
        if kind == "app":
            apps = cond.get("applications") or {}
            if _includes(apps, "includeApplications", value):
                return True
        else:
            users = cond.get("users") or {}
            if _includes(users, "includeUsers", "All") \
                    or _includes(users, "includeGroups", value):
                return True
    return False


def check_coverage(policies, config):
    """Return coverage findings for the given config."""
    findings = []
    for app in config.get("critical_apps") or []:
        if not _protected(policies, "app", app):
            findings.append({
                "check": "uncovered-app", "severity": "HIGH",
                "object": app,
                "message": f"critical app {app} has no enforced MFA/block policy",
            })
    for group in config.get("user_groups") or []:
        if not _protected(policies, "group", group):
            findings.append({
                "check": "uncovered-group", "severity": "HIGH",
                "object": group,
                "message": f"user group {group} has no enforced MFA/block policy",
            })
    for account in config.get("break_glass_accounts") or []:
        excluded = False
        for policy in policies:
            if not _is_enforced(policy):
                continue
            users = (policy.get("conditions") or {}).get("users") or {}
            excluded_users = users.get("excludeUsers") or []
            if account in excluded_users:
                excluded = True
                break
        if not excluded:
            findings.append({
                "check": "break-glass-not-excluded", "severity": "MEDIUM",
                "object": account,
                "message": f"break-glass account {account} is not excluded "
                           "from any enforced policy",
            })
    return findings
