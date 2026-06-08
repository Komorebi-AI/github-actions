"""MOCKUP / SPIKE — alternative detection backend using `uv audit`.

NOT wired into action.yml. This demonstrates how `update.py` would look if the
vulnerability *source* were `uv audit` (OSV-backed) instead of GitHub Dependabot
alerts. Everything downstream of detection — the remediation loop, the issue-#12
no-op/phantom gating, the PR builder — is imported unchanged from `update.py`.
Only `fetch_alerts()` is replaced (here: `fetch_alerts_uv_audit()`).

The point of the spike: see whether `uv audit` simplifies remediation + PR
creation. Short answer as of June 2026:

  * Detection: YES, this cleanly replaces the Dependabot `gh api` call, and
    because OSV evaluates the *installed* version against affected ranges, it
    sidesteps the stale "fixed == installed" false positive that caused #12.
  * Remediation/PR: NOT YET. `uv audit --fix` is on the roadmap but unshipped,
    so we still drive `uv lock --upgrade-package` exactly as today. The day
    `--fix` ships, `remediate_with_uv_fix()` below collapses most of
    update.upgrade_packages() into a couple of commands.

⚠️  CAVEAT: `uv audit`'s JSON output is newly stabilized and its exact schema is
not yet documented. The parser below models pip-audit's well-documented
`--format json` shape (uv audit is an explicit pip-audit alternative) as a
best-effort placeholder. Before using this for real, run
`uv audit --format json` on a vulnerable project and adjust `_parse_audit_json`
to match the actual field names.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Reuse the data model + all downstream logic untouched.
from update import (
    Advisory,
    VulnerablePackage,
    build_pr_body,
    create_or_update_pr,
    get_direct_dependencies,
    normalize_name,
    parse_version,
    run,
    upgrade_packages,
)


# ---------------------------------------------------------------------------
# Detection via `uv audit`  (replaces fetch_alerts())
# ---------------------------------------------------------------------------

def _highest_fix(fix_versions: list[str]) -> str | None:
    """Pick the highest fix version from an advisory's fix list (None if empty)."""
    if not fix_versions:
        return None
    return max(fix_versions, key=parse_version)


def _parse_audit_json(payload: dict) -> list[VulnerablePackage]:
    """Map `uv audit --format json` output to the existing VulnerablePackage model.

    Modelled on pip-audit's JSON shape (placeholder — verify against real uv
    audit output)::

        {
          "dependencies": [
            {
              "name": "urllib3",
              "version": "2.6.3",
              "vulns": [
                {
                  "id": "GHSA-xxxx-yyyy-zzzz",
                  "aliases": ["CVE-2026-44431"],
                  "fix_versions": ["2.7.0"],
                  "description": "…",
                  "severity": "high"
                }
              ]
            }
          ]
        }
    """
    grouped: dict[str, VulnerablePackage] = {}

    for dep in payload.get("dependencies", []):
        vulns = dep.get("vulns") or []
        if not vulns:
            continue  # OSV only lists a dep here if its version is in-range
        name = dep["name"]

        for v in vulns:
            ident = v.get("id", "")
            aliases = v.get("aliases", []) or []
            cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
            ghsa = ident if ident.upper().startswith("GHSA-") else None
            # If the primary id wasn't a GHSA, fall back to any GHSA alias.
            if ghsa is None:
                ghsa = next((a for a in aliases if a.upper().startswith("GHSA-")), ident)

            advisory = Advisory(
                ghsa=ghsa,
                cve=cve,
                summary=v.get("description") or v.get("summary") or "",
                severity=(v.get("severity") or "unknown").lower(),
            )
            fixed = _highest_fix(v.get("fix_versions", []) or [])

            if name not in grouped:
                grouped[name] = VulnerablePackage(name=name, fixed=fixed)
            elif fixed and (
                grouped[name].fixed is None
                or parse_version(fixed) > parse_version(grouped[name].fixed)
            ):
                grouped[name].fixed = fixed
            grouped[name].advisories.append(advisory)

    return list(grouped.values())


def fetch_alerts_uv_audit() -> list[VulnerablePackage]:
    """Detect vulnerable packages by running `uv audit` against the lockfile.

    Drop-in replacement for update.fetch_alerts(repo). Note it needs no repo
    argument and no GH token — it reads the local uv.lock, so it also works on
    forks / pre-merge where Dependabot's alert API may not be populated.
    """
    # `uv audit` exits non-zero when it finds vulnerabilities, so check=False.
    result = run(["uv", "audit", "--format", "json"], check=False)
    if result.returncode not in (0, 1):  # 1 == findings; anything else is an error
        print(f"uv audit failed (exit {result.returncode}): {result.stderr.strip()}")
        return []
    if not result.stdout.strip():
        return []
    return _parse_audit_json(json.loads(result.stdout))


# ---------------------------------------------------------------------------
# FUTURE: once `uv audit --fix` ships, remediation collapses to this.
# ---------------------------------------------------------------------------

def remediate_with_uv_fix() -> bool:
    """Sketch of the post-`--fix` world. Returns True if anything changed.

    This would replace update.upgrade_packages() entirely: a single command
    applies the minimal compatible upgrades, and the existing `git diff uv.lock`
    gate in create_or_update_pr() already handles the "nothing changed" case.
    The #12 no-op problem largely disappears because --fix only touches packages
    with an in-range vulnerability and an available fix.
    """
    result = run(["uv", "audit", "--fix"], check=False)
    print(result.stdout)
    # Real impl: detect change via `git diff --quiet uv.lock` instead of stdout.
    return "updated" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Main — identical flow to update.main(), only the detection call differs.
# ---------------------------------------------------------------------------

def main() -> None:
    branch_name = os.environ.get("INPUT_BRANCH_NAME", "security/dependency-updates")
    pr_title = os.environ.get("INPUT_PR_TITLE", "security: upgrade vulnerable dependencies")
    lockfile = Path("uv.lock")
    pyproject = Path("pyproject.toml")

    packages = fetch_alerts_uv_audit()
    print(f"Packages with vulnerabilities (uv audit): {len(packages)}")

    if not packages:
        print("No vulnerabilities reported — nothing to do.")
        return

    direct_deps = get_direct_dependencies(pyproject)
    results = upgrade_packages(packages, lockfile)
    pr_body = build_pr_body(packages, results, direct_deps)
    create_or_update_pr(pr_body, branch_name, pr_title)


if __name__ == "__main__":
    main()
