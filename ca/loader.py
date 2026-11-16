"""Load Entra ID Conditional Access policy exports (JSON)."""

import json


def load_policies(path):
    """Load a policy export: a JSON list of policy objects."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("policy file must contain a policy object or a list")


def display_name(policy):
    """Human label for a policy."""
    return policy.get("displayName") or policy.get("id") or "<unnamed>"


def conditions(policy):
    """Return the conditions dict, defaulting missing parts to {}."""
    return policy.get("conditions") or {}


def grant_controls(policy):
    """Return the grantControls dict, defaulting missing parts to {}."""
    return policy.get("grantControls") or {}
