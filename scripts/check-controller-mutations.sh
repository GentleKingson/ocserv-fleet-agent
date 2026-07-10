#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPO_ROOT

if ! command -v python3 >/dev/null 2>&1; then
  printf 'controller mutation SQL guard requires python3\n' >&2
  exit 2
fi

policy_root="$REPO_ROOT"
if [[ "${1:-}" == "--repo-root" ]]; then
  if [[ "$#" -lt 2 ]]; then
    printf 'usage: %s [--repo-root <path>] [scan-path ...]\n' "$0" >&2
    exit 2
  fi
  policy_root="$2"
  shift 2
fi

if [[ ! -d "$policy_root" ]]; then
  printf 'controller mutation SQL repository root not found: %s\n' "$policy_root" >&2
  exit 2
fi

declare -a scan_roots=()
if [[ "$#" -eq 0 ]]; then
  scan_roots=(
    "$policy_root/crates/ocfleet-cli"
    "$policy_root/crates/ocfleet-api"
  )
else
  scan_roots=("$@")
fi

for root in "${scan_roots[@]}"; do
  if [[ ! -e "$root" ]]; then
    printf 'controller mutation SQL scan path not found: %s\n' "$root" >&2
    exit 2
  fi
done

python3 - "$policy_root" "${scan_roots[@]}" <<'PY'
import os
import re
import sys
from pathlib import Path


repo_root = Path(sys.argv[1]).resolve()
scan_roots = [Path(value).resolve() for value in sys.argv[2:]]

# Keep this list deliberately small. A new backend must first establish a
# reviewed transactional writer boundary before its path is added here.
ALLOWED_FILES = {
    ("crates", "ocfleet-cli", "src", "store.rs"),
    ("crates", "ocfleet-cli", "src", "migrations.rs"),
}
ALLOWED_DIRECTORIES = {
    ("crates", "ocfleet-cli", "migrations"),
}
EXCLUDED_DIRECTORIES = {
    ".git",
    "benches",
    "fixtures",
    "target",
    "testdata",
    "tests",
}

MUTATION_RE = re.compile(
    r"\b(?:"
    r"INSERT\s+(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)\s+)?INTO"
    r"|REPLACE\s+INTO"
    r"|UPDATE\s+(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)\s+)?"
    r"(?:ONLY\s+)?[A-Z0-9_$\.\[\]`\"]+\s+SET"
    r"|DELETE\s+FROM"
    r"|MERGE\s+INTO"
    r"|TRUNCATE\s+(?:TABLE\s+)?[A-Z0-9_$\.\[\]`\"]+"
    r"|CREATE\s+(?:(?:OR\s+REPLACE|TEMP(?:ORARY)?|UNIQUE)\s+)*"
    r"(?:TABLE|INDEX|TRIGGER|VIEW)"
    r"|ALTER\s+TABLE"
    r"|DROP\s+(?:TABLE|INDEX|TRIGGER|VIEW)"
    r")\b",
    re.IGNORECASE,
)
LEGACY_SCHEDULER_WRITER_RE = re.compile(
    r"(?:\.\s*|\bStore\s*::\s*)"
    r"(insert_observability_run|finish_observability_run|"
    r"insert_probe_observation|update_observability_job_run_times)\s*\("
)
DIRECT_NODE_ENDPOINT_MUTATOR_RE = re.compile(
    r"(?:\.\s*|\bStore\s*::\s*)"
    r"(add_node|enable_node|disable_node|remove_node|rotate_endpoint|"
    r"revoke_endpoint|quarantine_endpoint)\s*\("
)
DIRECT_ENROLLMENT_MUTATOR_RE = re.compile(
    r"(?:\.\s*|\bStore\s*::\s*)"
    r"(approve_join_request|claim_legacy_enrollment)\s*\("
)
DIRECT_RPC_AUDIT_RE = re.compile(r"\bwrite_rpc_audit\s*\(")
LEGACY_SCHEDULER_WRITER_ALLOWED_FILES = {
    ("crates", "ocfleet-cli", "src", "store.rs"),
}
DIRECT_NODE_ENDPOINT_MUTATOR_ALLOWED_FILES = {
    ("crates", "ocfleet-cli", "src", "store.rs"),
    ("crates", "ocfleet-cli", "src", "backend.rs"),
}
DIRECT_ENROLLMENT_MUTATOR_ALLOWED_FILES = {
    ("crates", "ocfleet-cli", "src", "store.rs"),
    ("crates", "ocfleet-cli", "src", "backend.rs"),
}
DIRECT_RPC_AUDIT_ALLOWED_FILES = {
    ("crates", "ocfleet-cli", "src", "controller_rpc.rs"),
    ("crates", "ocfleet-cli", "src", "main.rs"),
}
CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")


def is_allowed(path):
    try:
        relative = path.resolve().relative_to(repo_root)
    except ValueError:
        return False
    parts = relative.parts
    if parts in ALLOWED_FILES:
        return True
    return any(parts[: len(directory)] == directory for directory in ALLOWED_DIRECTORIES)


def iter_source_files(root):
    if root.is_file():
        if root.suffix in {".rs", ".sql"}:
            yield root
        return

    for current, directories, filenames in os.walk(root):
        directories[:] = sorted(
            name for name in directories if name not in EXCLUDED_DIRECTORIES
        )
        base = Path(current)
        for filename in sorted(filenames):
            path = base / filename
            if path.suffix in {".rs", ".sql"}:
                yield path


def mask(chars, start, end):
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def rust_views(source):
    """Return comment-free search text and a string/comment-free brace view."""
    searchable = list(source)
    structure = list(source)
    length = len(source)
    index = 0

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            mask(searchable, index, end)
            mask(structure, index, end)
            index = end
            continue

        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            mask(searchable, index, end)
            mask(structure, index, end)
            index = end
            continue

        raw = re.match(r"(?:br|rb|r)(#{0,255})\"", source[index:])
        if raw and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")):
            hashes = raw.group(1)
            content_start = index + raw.end()
            terminator = '"' + hashes
            close = source.find(terminator, content_start)
            end = length if close == -1 else close + len(terminator)
            mask(structure, index, end)
            index = end
            continue

        prefix_length = 0
        if source[index] == '"':
            prefix_length = 0
        elif (
            index + 1 < length
            and source[index] in {"b", "c"}
            and source[index + 1] == '"'
            and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_"))
        ):
            prefix_length = 1
        else:
            prefix_length = -1

        if prefix_length >= 0:
            end = index + prefix_length + 1
            escaped = False
            while end < length:
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            mask(structure, index, end)
            index = end
            continue

        index += 1

    return "".join(searchable), "".join(structure)


def test_only_ranges(structure):
    ranges = []
    for attribute in CFG_TEST_RE.finditer(structure):
        brace = structure.find("{", attribute.end())
        semicolon = structure.find(";", attribute.end())
        if semicolon != -1 and (brace == -1 or semicolon < brace):
            ranges.append((attribute.start(), semicolon + 1))
            continue
        if brace == -1:
            ranges.append((attribute.start(), len(structure)))
            continue

        depth = 1
        end = brace + 1
        while end < len(structure) and depth:
            if structure[end] == "{":
                depth += 1
            elif structure[end] == "}":
                depth -= 1
            end += 1
        ranges.append((attribute.start(), end))
    return ranges


def rust_search_text(source):
    searchable, structure = rust_views(source)
    chars = list(searchable)
    for start, end in test_only_ranges(structure):
        mask(chars, start, end)
    return "".join(chars)


def rust_code_text(source):
    _, structure = rust_views(source)
    chars = list(structure)
    for start, end in test_only_ranges(structure):
        mask(chars, start, end)
    return "".join(chars)


def sql_search_text(source):
    chars = list(source)
    index = 0
    while index < len(source):
        if source.startswith("--", index):
            end = source.find("\n", index + 2)
            end = len(source) if end == -1 else end
            mask(chars, index, end)
            index = end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = len(source) if end == -1 else end + 2
            mask(chars, index, end)
            index = end
        else:
            index += 1
    return "".join(chars)


def display_path(path):
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


files = sorted({path for root in scan_roots for path in iter_source_files(root)})
if not files:
    print("controller mutation SQL guard found no source files", file=sys.stderr)
    sys.exit(2)

violations = []
checked = 0
for path in files:
    checked += 1
    source = path.read_text(encoding="utf-8")
    if not is_allowed(path):
        searchable = rust_search_text(source) if path.suffix == ".rs" else sql_search_text(source)
        for match in MUTATION_RE.finditer(searchable):
            line = source.count("\n", 0, match.start()) + 1
            statement = " ".join(match.group(0).split())
            violations.append(
                (
                    display_path(path),
                    line,
                    "controller mutation SQL outside reviewed store/migration location",
                    statement,
                )
            )

    if path.suffix != ".rs":
        continue
    try:
        parts = path.resolve().relative_to(repo_root).parts
    except ValueError:
        parts = ()
    code = rust_code_text(source)
    if parts not in LEGACY_SCHEDULER_WRITER_ALLOWED_FILES:
        for match in LEGACY_SCHEDULER_WRITER_RE.finditer(code):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(
                (
                    display_path(path),
                    line,
                    "legacy scheduler persistence call outside transactional writer boundary",
                    match.group(1),
                )
            )
    if parts not in DIRECT_NODE_ENDPOINT_MUTATOR_ALLOWED_FILES:
        for match in DIRECT_NODE_ENDPOINT_MUTATOR_RE.finditer(code):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(
                (
                    display_path(path),
                    line,
                    "direct node/endpoint mutator call outside reviewed store/backend boundary",
                    match.group(1),
                )
            )
    if parts not in DIRECT_ENROLLMENT_MUTATOR_ALLOWED_FILES:
        for match in DIRECT_ENROLLMENT_MUTATOR_RE.finditer(code):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(
                (
                    display_path(path),
                    line,
                    "direct enrollment mutator call outside reviewed store/backend boundary",
                    match.group(1),
                )
            )
    if parts not in DIRECT_RPC_AUDIT_ALLOWED_FILES:
        for match in DIRECT_RPC_AUDIT_RE.finditer(code):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(
                (
                    display_path(path),
                    line,
                    "direct RPC audit write outside reviewed caller boundary",
                    "write_rpc_audit",
                )
            )

for path, line, message, statement in violations:
    print(f"{path}:{line}: {message}: {statement}", file=sys.stderr)

if violations:
    print(
        f"Controller mutation SQL guard failed with {len(violations)} violation(s).",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"Controller mutation SQL guard passed for {checked} production source file(s).")
PY
