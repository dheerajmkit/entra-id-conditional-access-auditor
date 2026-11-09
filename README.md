# entra-id-conditional-access-auditor

Audits Microsoft Entra ID Conditional Access policy exports (JSON) for
coverage gaps: disabled or report-only policies, missing MFA controls,
legacy authentication allowed, risky sign-ins not blocked, and policies
with no users or apps in scope.

This is a **personal portfolio project** exploring Entra ID Conditional
Access analysis and security automation. It is a learning exercise, not
a production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/policies.json
```

Exit codes: `2` = usage error or unreadable export, `1` = at least one
high finding, `0` = no high findings.

## Day-1 scope

- Policy loading: JSON exports (a list of policy objects).
- Checks: disabled policies, report-only policies, missing MFA
  controls, legacy auth client app types, risky sign-ins not blocked,
  empty user/app scope.
- Text and JSON (`--json`) findings reports with severity counts.
