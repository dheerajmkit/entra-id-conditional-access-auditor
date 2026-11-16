"""Coverage-gap checks for Conditional Access policies."""

from .loader import display_name, conditions, grant_controls

LEGACY_APP_TYPES = ("exchangeActiveSync", "other")


def check_policy(policy):
    """Return findings for one policy."""
    name = display_name(policy)
    state = str(policy.get("state", "")).lower()
    cond = conditions(policy)
    grants = grant_controls(policy)
    controls = [str(c).lower() for c in grants.get("builtInControls") or []]
    findings = []

    if state == "disabled":
        findings.append({
            "check": "policy-disabled", "severity": "HIGH", "object": name,
            "message": f"policy {name} is disabled",
        })
        return findings  # Disabled policies enforce nothing else.
    if state == "reportonly":
        findings.append({
            "check": "policy-report-only", "severity": "MEDIUM",
            "object": name,
            "message": f"policy {name} is report-only, not enforced",
        })

    users = cond.get("users") or {}
    apps = cond.get("applications") or {}
    if not (users.get("includeUsers") or users.get("includeGroups")):
        findings.append({
            "check": "no-users-in-scope", "severity": "MEDIUM",
            "object": name,
            "message": f"policy {name} includes no users or groups",
        })
    if not apps.get("includeApplications"):
        findings.append({
            "check": "no-apps-in-scope", "severity": "MEDIUM",
            "object": name,
            "message": f"policy {name} includes no applications",
        })

    if "mfa" not in controls and "block" not in controls \
            and not grants.get("authenticationStrength"):
        findings.append({
            "check": "no-mfa-control", "severity": "HIGH", "object": name,
            "message": f"policy {name} requires neither MFA nor block",
        })

    app_types = [str(t) for t in cond.get("clientAppTypes") or []]
    if any(t in LEGACY_APP_TYPES for t in app_types) \
            and "block" not in controls:
        findings.append({
            "check": "legacy-auth-allowed", "severity": "HIGH",
            "object": name,
            "message": f"policy {name} allows legacy auth client types",
        })

    risk_levels = [str(r).lower()
                   for r in cond.get("signInRiskLevels") or []]
    if "high" in risk_levels and "block" not in controls:
        findings.append({
            "check": "risky-signin-not-blocked", "severity": "MEDIUM",
            "object": name,
            "message": f"policy {name} sees high-risk sign-ins but does not block",
        })

    return findings


def check_policies(policies):
    """Return all findings for a list of policies."""
    findings = []
    for policy in policies:
        findings.extend(check_policy(policy))
    return findings
