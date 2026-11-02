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

VERIFIED against a real `uv audit --output-format json` run (uv 0.11.19,
schema {"version": "preview"}). Real top-level shape::

    {
      "schema": {"version": "preview"},
      "summary": {"audited_packages": 4, "vulnerabilities": 19, "adverse_statuses": 0},
      "vulnerabilities": [                     # FLAT list, one entry per advisory
        {
          "dependency": {"name": "jinja2", "version": "2.11.2"},
          "id": "GHSA-cpwx-vrp4-4pq7",         # GHSA-* or PYSEC-*
          "display_id": "GHSA-cpwx-vrp4-4pq7",
          "aliases": ["CVE-2025-27516"],       # CVE (+ sometimes GHSA/SNYK) live here
          "summary": "Jinja2 vulnerable to ...",  # can be null (e.g. PYSEC entries)
          "description": "...",
          "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-27516",
          "fix_versions": ["3.1.6"],           # list; pick the highest
          "published": "2025-03-05T20:40:14Z",
          "modified": "2026-02-04T04:14:58Z"
        }
      ],
      "adverse_statuses": []                   # PEP 792 statuses (deprecations etc.)
    }

⚠️  GAPS / things to know (as of uv 0.11.19):
  * NO severity/CVSS field — OSV output here carries none, so the existing
    PR table's "(severity)" column degrades to "(unknown)". This is the main
    thing we'd lose vs Dependabot. Could be backfilled from GHSA later.
  * `uv audit` is still behind a preview warning ("Pass
    `--preview-features audit-command` to disable this warning") and the
    schema self-reports {"version": "preview"} — expect churn.
  * Exit code is 1 when vulnerabilities are found, 0 when clean.
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
    """Map `uv audit --output-format json` output to the VulnerablePackage model.

    `payload["vulnerabilities"]` is a FLAT list (one entry per advisory), so we
    group by `dependency.name` and keep the highest fix across a package's
    advisories — mirroring how fetch_alerts() folds Dependabot alerts.
    """
    grouped: dict[str, VulnerablePackage] = {}

    for v in payload.get("vulnerabilities", []):
        name = v["dependency"]["name"]
        ident = v.get("id", "") or ""
        aliases = v.get("aliases", []) or []

        cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
        if cve is None and ident.upper().startswith("CVE-"):
            cve = ident
        ghsa = ident if ident.upper().startswith("GHSA-") else None
        if ghsa is None:
            # PYSEC-* primaries often carry the GHSA in aliases; fall back to
            # the primary id (e.g. PYSEC-…) so the row is still identifiable.
            ghsa = next((a for a in aliases if a.upper().startswith("GHSA-")), ident)

        advisory = Advisory(
            ghsa=ghsa,
            cve=cve,
            # `summary` can be null (PYSEC entries); fall back to the first
            # line of the description.
            summary=v.get("summary") or (v.get("description") or "").split("\n", 1)[0],
            # NOTE: uv audit's OSV output exposes no severity — see module
            # docstring. Marked "unknown"; would need a GHSA lookup to enrich.
            severity="unknown",
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
    # `uv audit` exits 1 when it finds vulnerabilities, 0 when clean, so
    # check=False. The preview warning goes to stderr; JSON to stdout.
    result = run(["uv", "audit", "--output-format", "json"], check=False)
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

    NOT YET AVAILABLE: `uv audit --help` on 0.11.19 has no `--fix` flag; it is
    roadmap-only (astral-sh/uv#19428). This is what remediation *would* look
    like once it ships.

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
