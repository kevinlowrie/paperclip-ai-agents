#!/usr/bin/env python3
"""Branch-aware hook policy for paperclip-ai-agents and Homelab ecosystem repos.

FAST profile (default for WIP, worktree, feature, and stacked PR branches):
- Runs fast syntax/compile and secret-leak checks on changed files only.
- Skips full multi-suite CI on pre-push so dev agents inside local gang-leaders
  can rapidly commit, push, sync, pull, checkout, and repeat.

FULL profile (protected & release branches: main, master, testing, freeze,
release-candidate, release, prod, production):
- Enforces full domain verification on pre-commit and pre-push.
- Required before promoting to testing, freeze, release-candidate (A/B rollback,
  migration, telemetry), release (sanitized/pruned deployable artifacts), or
  prod (customer-live internal overlay).
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

# Per-repo full-gate command for protected branches.
# None = auto-detect (HOMELAB_FULL_GATE_CMD env, workstation acceptance,
#        make check, tests/ discovery, git status fallback).
FULL_GATE_CMD: tuple[str, ...] | None = ("node", "scripts/check-module-boundaries.mjs")

PROTECTED_EXACT = {
    "main",
    "master",
    "testing",
    "freeze",
    "release-candidate",
    "release",
    "prod",
    "production",
}
PROTECTED_PREFIXES = (
    "release/",
    "release-candidate/",
    "freeze/",
    "testing/",
    "prod/",
    "rc/",
)

SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(rb"(?:ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{32,}"),
)

SQLITE_AWARENESS_RE = re.compile(
    r"(?:openviking|awareness|agent[_-]memory).*\.(?:sqlite3?|db)$",
    re.IGNORECASE,
)


def current_branch(repo: Path = ROOT) -> str:
    for key in ("HOMELAB_HOOK_BRANCH", "GITHUB_REF_NAME", "CI_COMMIT_BRANCH"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    proc = subprocess.run(
        ["git", "-C", str(repo), "branch", "--show-current"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def is_protected(branch: str) -> bool:
    b = (branch or "").strip()
    if not b:
        return os.environ.get("CI", "").lower() == "true"
    if b in PROTECTED_EXACT:
        return True
    return any(b.startswith(p) for p in PROTECTED_PREFIXES)


def resolve_profile(branch: str) -> str:
    override = os.environ.get("HOOK_PROFILE", "").strip().lower()
    if override in {"fast", "full"}:
        return override
    return "full" if is_protected(branch) else "fast"


def staged_files(repo: Path = ROOT) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def check_files_fast(repo: Path, rel_paths: list[str]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for rel in rel_paths:
        if SQLITE_AWARENESS_RE.search(rel):
            errors.append(f"SQLite agent-awareness drift forbidden (use OpenViking): {rel}")
            continue
        p = (repo / rel).resolve()
        if not p.is_file():
            continue
        data = p.read_bytes()
        for pat in SECRET_PATTERNS:
            if pat.search(data):
                errors.append(f"Potential secret material detected in {rel}")
                break
        if p.suffix == ".py":
            try:
                compile(data, str(p), "exec")
            except SyntaxError as exc:
                errors.append(f"Python syntax check failed in {rel}:{exc.lineno}: {exc.msg}")
    return (len(errors) == 0, errors)


def run_full_gate(repo: Path = ROOT) -> int:
    if FULL_GATE_CMD:
        cmd = list(FULL_GATE_CMD)
    else:
        custom = os.environ.get("HOMELAB_FULL_GATE_CMD", "").strip()
        if custom:
            cmd = custom.split()
        elif (repo / "workstation" / "acceptance").is_dir() and (repo / "Makefile").is_file():
            cmd = [sys.executable, "-B", "-m", "unittest", "discover",
                   "-s", "workstation/acceptance", "-v"]
        elif (repo / "Makefile").is_file():
            cmd = ["make", "check"]
        elif (repo / "tests").is_dir():
            cmd = [sys.executable, "-B", "-m", "unittest", "discover",
                   "-s", "tests", "-v"]
        else:
            cmd = ["git", "status", "-sb"]
    print("+ " + " ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=repo, check=False)
    if result.returncode != 0:
        print(
            "[hook-policy] FULL gate failed (exit %d). "
            "Install deps (npm install / pip install) or fix the failure, "
            "or set HOOK_PROFILE=fast for a WIP branch." % result.returncode,
            file=sys.stderr,
        )
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args or args[0] not in {"pre-commit", "pre-push", "status"}:
        print("usage: hook_policy.py <pre-commit|pre-push|status> [files...]",
              file=sys.stderr)
        return 2
    stage = args[0]
    repo = Path(os.environ.get("HOMELAB_HOOK_REPO", str(ROOT))).resolve()
    branch = current_branch(repo)
    prof = resolve_profile(branch)
    if stage == "status":
        print(f"branch={branch or '(detached)'} profile={prof} "
              f"protected={is_protected(branch)}")
        return 0
    if stage == "pre-commit":
        files = args[1:] or staged_files(repo)
        print(f"[hook-policy] stage=pre-commit branch={branch or '(detached)'} "
              f"profile={prof} files={len(files)}")
        ok, errors = check_files_fast(repo, files)
        if not ok:
            for err in errors:
                print(f"[hook-policy] ERROR: {err}", file=sys.stderr)
            return 1
        if prof == "full":
            return run_full_gate(repo)
        return 0
    print(f"[hook-policy] stage=pre-push branch={branch or '(detached)'} "
          f"profile={prof}")
    if prof == "full":
        return run_full_gate(repo)
    print("[hook-policy] FAST profile active on WIP/PR branch: "
          "skipping full pre-push harness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
