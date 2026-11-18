#!/bin/sh
# Audit the sample policies, with and without coverage analysis.
set -e
cd "$(dirname "$0")/.."
python3 run.py samples/policies.json --coverage samples/coverage-config.json || true
python3 -m unittest discover -s tests -v
