"""Unit tests for the Conditional Access checks and coverage analysis.

Run from the project root:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca.checks import check_policy
from ca.coverage import check_coverage


def policy(name="P1", state="enabled", controls=("mfa",), **cond):
    base = {"displayName": name, "state": state,
            "grantControls": {"builtInControls": list(controls)},
            "conditions": {"users": {"includeUsers": ["All"]},
                           "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["browser"]}}
    base["conditions"].update(cond)
    return base


class TestChecks(unittest.TestCase):
    def test_clean_mfa_policy(self):
        self.assertEqual(check_policy(policy()), [])

    def test_disabled_is_high(self):
        findings = check_policy(policy(state="disabled"))
        self.assertTrue(any(f["check"] == "policy-disabled"
                            and f["severity"] == "HIGH" for f in findings))

    def test_report_only_is_medium(self):
        findings = check_policy(policy(state="reportOnly"))
        self.assertTrue(any(f["check"] == "policy-report-only"
                            for f in findings))

    def test_no_mfa_control_is_high(self):
        findings = check_policy(policy(controls=()))
        self.assertTrue(any(f["check"] == "no-mfa-control"
                            for f in findings))

    def test_legacy_auth_is_high(self):
        findings = check_policy(policy(clientAppTypes=["other"]))
        self.assertTrue(any(f["check"] == "legacy-auth-allowed"
                            for f in findings))

    def test_legacy_auth_blocked_is_clean(self):
        findings = check_policy(policy(clientAppTypes=["other"],
                                      controls=("block",)))
        self.assertEqual(findings, [])

    def test_risky_signin_not_blocked(self):
        findings = check_policy(policy(signInRiskLevels=["high"]))
        self.assertTrue(any(f["check"] == "risky-signin-not-blocked"
                            for f in findings))


class TestCoverage(unittest.TestCase):
    def test_uncovered_app(self):
        findings = check_coverage(
            [policy()], {"critical_apps": ["Acme VPN"], "user_groups": []})
        self.assertEqual(findings, [])  # "All" apps policy covers it

    def test_no_policy_covers_app(self):
        p = policy()
        p["conditions"]["applications"] = {"includeApplications": ["Teams"]}
        findings = check_coverage(
            [p], {"critical_apps": ["Acme VPN"], "user_groups": []})
        self.assertTrue(any(f["check"] == "uncovered-app"
                            for f in findings))

    def test_break_glass_excluded_is_clean(self):
        p = policy()
        p["conditions"]["users"]["excludeUsers"] = ["breakglass@acme.example"]
        findings = check_coverage(
            [p], {"break_glass_accounts": ["breakglass@acme.example"]})
        self.assertEqual(findings, [])

    def test_break_glass_not_excluded(self):
        findings = check_coverage(
            [policy()],
            {"break_glass_accounts": ["breakglass@acme.example"]})
        self.assertTrue(any(f["check"] == "break-glass-not-excluded"
                            for f in findings))


if __name__ == "__main__":
    unittest.main()
