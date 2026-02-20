#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for opencode-security-filter.

Reads tool invocation JSON from stdin, extracts file paths,
and checks each against the security filter CLI. Blocks the
tool call if any path is denied.
"""

import json
import shlex
import shutil
import subprocess
import sys

FILTER_CMD = "opencode-security-filter"


def extract_paths(tool_name: str, tool_input: dict) -> list[str]:
    """Extract file paths from tool input based on tool type."""
    paths: list[str] = []

    if tool_name in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)
        # MultiEdit may have multiple edits with file_path
        for edit in tool_input.get("edits", []):
            fp = edit.get("file_path", "")
            if fp:
                paths.append(fp)

    elif tool_name in ("Glob", "Grep"):
        p = tool_input.get("path", "")
        if p:
            paths.append(p)

    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            paths.extend(_paths_from_bash(command))

    return paths


def _paths_from_bash(command: str) -> list[str]:
    """Best-effort path extraction from a bash command string.

    Extracts tokens that look like file paths (contain / or ~).
    The Python security filter CLI decides what's actually blocked.
    """
    paths: list[str] = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        return paths

    for token in tokens:
        if token.startswith("-"):
            continue
        if "/" in token or token.startswith("~"):
            paths.append(token)

    return paths


def check_path(path: str) -> tuple[bool, str]:
    """Check a path via the security filter CLI.

    Returns (allowed, reason).
    """
    try:
        result = subprocess.run(
            [FILTER_CMD, "--check", path],
            capture_output=True,
            text=True,
            timeout=5,
        )

        output = result.stdout
        decision = "pass"
        reason = "No matching pattern"

        for line in output.splitlines():
            if line.startswith("Decision:"):
                decision = line.split(":", 1)[1].strip()
            elif line.startswith("Reason:"):
                reason = line.split(":", 1)[1].strip()

        return (decision != "deny", reason)

    except FileNotFoundError:
        return (True, "Filter not installed")
    except subprocess.TimeoutExpired:
        return (True, "Filter timed out")
    except Exception:
        return (True, "Filter unavailable")


def main() -> None:
    if not shutil.which(FILTER_CMD):
        sys.exit(0)

    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    paths = extract_paths(tool_name, tool_input)

    for path in paths:
        allowed, reason = check_path(path)
        if not allowed:
            print(
                f"SECURITY BLOCK: Access to {path} denied. {reason}",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
