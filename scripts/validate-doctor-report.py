#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def fail(message):
    print(f"doctor report validation failed: {message}", file=sys.stderr)
    return 1


def is_plain_int(value):
    return type(value) is int


def validate(report):
    if report.get("status") not in {"ok", "warning"}:
        return fail("status must be ok or warning")
    if report.get("exit_code") != 0:
        return fail("exit_code must be 0")

    expected = report.get("schema_version_expected")
    actual = report.get("schema_version_actual")
    if not is_plain_int(expected) or not is_plain_int(actual):
        return fail("schema_version_expected and schema_version_actual must be integers")
    if expected != actual:
        return fail(
            "schema_version_expected does not match schema_version_actual "
            f"({expected} != {actual})"
        )
    if expected < 1:
        return fail("schema_version_expected must be positive")

    if not isinstance(report.get("checks"), list):
        return fail("checks must be a list")

    return 0


def main(argv):
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <doctor-report.json>", file=sys.stderr)
        return 2

    with open(argv[1], "r", encoding="utf-8") as handle:
        report = json.load(handle)
    return validate(report)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
