#!/usr/bin/env python3
"""Audit Entra ID Conditional Access policy exports for coverage gaps.

Usage:
    python3 run.py <policies.json> [--json]

Exit codes: 2 = usage error / unreadable export,
            1 = at least one high finding,
            0 = no high findings.
"""

import argparse
import sys

from ca.loader import load_policies
from ca.checks import check_policies
from ca.report import summarize, render_text, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policies", help="policy export JSON file")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        policies = load_policies(args.policies)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load policies: {exc}", file=sys.stderr)
        return 2

    findings = check_policies(policies)

    if args.json:
        print(render_json(args.policies, findings))
    else:
        print(render_text(args.policies, findings))

    counts = summarize(findings)
    return 1 if counts["HIGH"] or counts["CRITICAL"] else 0


if __name__ == "__main__":
    sys.exit(main())
