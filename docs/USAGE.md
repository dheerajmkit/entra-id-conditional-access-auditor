# Usage

## Auditing a policy export

```bash
python3 run.py policies.json
python3 run.py policies.json --json   # machine-readable output
```

Exit code `1` means at least one HIGH finding; `0` means none;
`2` means the file could not be read or parsed.

## Coverage analysis

```bash
python3 run.py policies.json --coverage coverage-config.json
```

The config lists the things that must be protected:

```json
{
  "break_glass_accounts": ["breakglass@acme.example"],
  "critical_apps": ["Office 365 Exchange Online", "Acme VPN"],
  "user_groups": ["Engineering", "Finance"]
}
```

An app or group counts as protected when an *enabled* policy includes
it and requires MFA, a block, or an authentication strength. Break-glass
accounts should be *excluded* from enforced policies.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| policy-disabled | HIGH | policy is disabled |
| no-mfa-control | HIGH | policy requires neither MFA nor block |
| legacy-auth-allowed | HIGH | legacy client app types allowed |
| uncovered-app | HIGH | critical app has no enforced MFA/block policy |
| uncovered-group | HIGH | user group has no enforced MFA/block policy |
| policy-report-only | MEDIUM | policy is report-only, not enforced |
| no-users-in-scope | MEDIUM | policy includes no users/groups |
| no-apps-in-scope | MEDIUM | policy includes no applications |
| risky-signin-not-blocked | MEDIUM | high-risk sign-ins seen but not blocked |
| break-glass-not-excluded | MEDIUM | break-glass account not excluded anywhere |

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```
