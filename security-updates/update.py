"""Upgrade vulnerable dependencies (direct and transitive) in uv.lock.

Reads open Dependabot alerts for the pip ecosystem, runs
``uv lock --upgrade-package`` for each affected package, and opens
(or updates) a single PR with a summary of what changed.

Environment variables (set by the composite action):
    GH_TOKEN          – GitHub PAT with repo scope
    GITHUB_REPOSITORY – owner/repo (set by Actions automatically)
    INPUT_BRANCH_NAME – branch to push the changes to
    INPUT_PR_TITLE    – title for the pull request
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kwargs)


def gh(*args: str) -> str:
    result = run(["gh", *args])
    return result.stdout


def git(*args: str) -> str:
    result = run(["git", *args])
    return result.stdout


def parse_version(v: str) -> tuple[int, ...]:
    """Best-effort parse of a PEP 440-ish version into a comparable tuple."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


def normalize_name(name: str) -> str:
    """PEP 503 normalize a package name for comparison."""
    return re.sub(r"[-_.]+", "-", name).lower()


def get_direct_dependencies(pyproject_path: Path) -> set[str]:
    """Extract direct dependency names from pyproject.toml (normalized)."""
    if not pyproject_path.exists():
        return set()

    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    direct: set[str] = set()

    # [project.dependencies]
    for dep in data.get("project", {}).get("dependencies", []):
        name = re.split(r"[>=<!\[;@\s]", dep)[0].strip()
        direct.add(normalize_name(name))

    # [project.optional-dependencies]
    for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
        for dep in group_deps:
            name = re.split(r"[>=<!\[;@\s]", dep)[0].strip()
            direct.add(normalize_name(name))

    # [dependency-groups] (uv / PEP 735)
    for group_deps in data.get("dependency-groups", {}).values():
        for dep in group_deps:
            if isinstance(dep, str):
                name = re.split(r"[>=<!\[;@\s]", dep)[0].strip()
                direct.add(normalize_name(name))

    return direct


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    ghsa: str | None
    cve: str | None
    summary: str
    severity: str

    def markdown_link(self) -> str:
        if self.cve:
            return f"[{self.cve}](https://nvd.nist.gov/vuln/detail/{self.cve})"
        return f"[{self.ghsa}](https://github.com/advisories/{self.ghsa})"

    def __str__(self) -> str:
        return f"{self.markdown_link()} ({self.severity}): {self.summary}"


@dataclass
class VulnerablePackage:
    name: str
    fixed: str | None  # highest fix version needed, None if no fix available
    advisories: list[Advisory] = field(default_factory=list)


@dataclass
class UpgradeResult:
    before: str
    after: str
    collateral: list[tuple[str, str | None, str | None]] = field(default_factory=list)
    """Other packages changed by this upgrade: (name, old_version, new_version).
    old_version is None if the package was added, new_version is None if removed."""


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def fetch_alerts(repo: str) -> list[VulnerablePackage]:
    """Fetch open Dependabot alerts and group by package."""
    raw = gh(
        "api", f"/repos/{repo}/dependabot/alerts",
        "--jq", (
            '[.[] | select(.state == "open" and '
            '.dependency.package.ecosystem == "pip") | '
            "{"
            "name: .dependency.package.name, "
            "fixed: .security_vulnerability.first_patched_version.identifier, "
            "ghsa: .security_advisory.ghsa_id, "
            "cve: .security_advisory.cve_id, "
            "summary: .security_advisory.summary, "
            "severity: .security_advisory.severity"
            "}]"
        ),
    )
    alerts = json.loads(raw)

    # Group by package name
    grouped: dict[str, VulnerablePackage] = {}
    for a in alerts:
        name = a["name"]
        fixed = a.get("fixed")
        advisory = Advisory(
            ghsa=a.get("ghsa"),
            cve=a.get("cve"),
            summary=a["summary"],
            severity=a["severity"],
        )
        if name not in grouped:
            grouped[name] = VulnerablePackage(name=name, fixed=fixed)
        else:
            # Keep the highest fix version (None means no known fix)
            if fixed and (
                grouped[name].fixed is None
                or parse_version(fixed) > parse_version(grouped[name].fixed)
            ):
                grouped[name].fixed = fixed
        grouped[name].advisories.append(advisory)

    return list(grouped.values())


_ALL_VERSIONS_RE = re.compile(
    r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"',
    re.MULTILINE,
)


def read_all_versions(lockfile_content: str | bytes) -> dict[str, str]:
    """Read all package versions from uv.lock content."""
    if isinstance(lockfile_content, bytes):
        lockfile_content = lockfile_content.decode()
    return dict(_ALL_VERSIONS_RE.findall(lockfile_content))


def read_version(pkg_name: str, lockfile: Path) -> str:
    """Read the current version of a package from uv.lock."""
    content = lockfile.read_text()
    pattern = re.compile(
        rf'^\[\[package\]\]\s*\nname\s*=\s*"{re.escape(pkg_name)}"\s*\nversion\s*=\s*"([^"]+)"',
        re.MULTILINE | re.IGNORECASE,
    )
    match = pattern.search(content)
    return match.group(1) if match else "unknown"


def _diff_versions(
    before: dict[str, str], after: dict[str, str], exclude: set[str],
) -> list[tuple[str, str | None, str | None]]:
    """Compute package version changes between two lockfile states.

    Returns a sorted list of (name, old_version, new_version) for every
    package that changed, was added (old=None), or was removed (new=None),
    excluding packages in *exclude*.
    """
    changes: list[tuple[str, str | None, str | None]] = []
    for name in sorted(set(before) | set(after)):
        if normalize_name(name) in exclude:
            continue
        old = before.get(name)
        new = after.get(name)
        if old != new:
            changes.append((name, old, new))
    return changes


def upgrade_packages(packages: list[VulnerablePackage], lockfile: Path) -> dict[str, UpgradeResult]:
    """Run uv lock --upgrade-package for each package.

    When the fix version is known, pin to that version to minimise churn.
    When unknown, upgrade to latest.

    Snapshots the lockfile before each attempt and restores it if the
    upgrade fails or produces a broken resolution (e.g. the package
    gets removed instead of upgraded because its dependencies can't be
    satisfied without upgrading other locked packages).

    Returns a dict of {package_name: UpgradeResult}.
    """
    results: dict[str, UpgradeResult] = {}
    target_names = {normalize_name(p.name) for p in packages}

    for pkg in packages:
        before = read_version(pkg.name, lockfile)
        if pkg.fixed:
            specifier = f"{pkg.name}=={pkg.fixed}"
        else:
            specifier = pkg.name

        snapshot = lockfile.read_bytes()
        versions_before = read_all_versions(snapshot)

        print(f"Upgrading {pkg.name} (current: {before}, target: {pkg.fixed or 'latest'})...")
        result = run(["uv", "lock", "--upgrade-package", specifier], check=False)

        if result.returncode != 0:
            print(f"  Warning: uv lock failed for {pkg.name}: {result.stderr.strip()}")
            lockfile.write_bytes(snapshot)
            results[pkg.name] = UpgradeResult(before=before, after=before)
            continue

        after = read_version(pkg.name, lockfile)

        # Validate the upgrade actually produced the expected result.
        # uv can silently produce a broken resolution (e.g. removing the
        # package entirely) when the target version's dependencies conflict
        # with other locked packages.
        if pkg.fixed:
            upgrade_ok = (
                after != "unknown"
                and parse_version(after) >= parse_version(pkg.fixed)
            )
        else:
            upgrade_ok = after != "unknown" and after != before

        if upgrade_ok:
            versions_after = read_all_versions(lockfile.read_bytes())
            collateral = _diff_versions(versions_before, versions_after, target_names)
            results[pkg.name] = UpgradeResult(
                before=before, after=after, collateral=collateral,
            )
        else:
            print(
                f"  Warning: upgrade did not produce expected result for {pkg.name} "
                f"(got {after}, need {pkg.fixed or 'newer than ' + before}), "
                f"restoring lockfile"
            )
            lockfile.write_bytes(snapshot)
            results[pkg.name] = UpgradeResult(before=before, after=before)

    return results


# ---------------------------------------------------------------------------
# PR body
# ---------------------------------------------------------------------------

def _render_table(rows: list[str], empty_message: str = "None.") -> list[str]:
    if not rows:
        return [empty_message]
    return [
        "| Package | Version | Needs | Vulnerabilities |",
        "|---|---|---|---|",
        *rows,
    ]


def _render_collateral(pkg_name: str, collateral: list[tuple[str, str | None, str | None]]) -> list[str]:
    """Render a collapsible details block for collateral changes."""
    if not collateral:
        return []
    n = len(collateral)
    lines = [
        "",
        "<details>",
        f"<summary><code>{pkg_name}</code> also changed {n} other "
        f"{'package' if n == 1 else 'packages'}</summary>",
        "",
        "| Package | Change |",
        "|---|---|",
    ]
    for name, old, new in collateral:
        if old is None:
            lines.append(f"| {name} | added {new} |")
        elif new is None:
            lines.append(f"| {name} | removed {old} |")
        else:
            lines.append(f"| {name} | {old} → {new} |")
    lines.append("")
    lines.append("</details>")
    return lines


def build_pr_body(
    packages: list[VulnerablePackage],
    results: dict[str, UpgradeResult],
    direct_deps: set[str],
) -> str:
    """Build a markdown PR body grouped by Direct / Transitive."""
    upgraded_direct: list[str] = []
    not_upgraded_direct: list[str] = []
    upgraded_transitive: list[str] = []
    not_upgraded_transitive: list[str] = []
    # Collateral details blocks, keyed by section ("direct" / "transitive")
    collateral_direct: list[list[str]] = []
    collateral_transitive: list[list[str]] = []

    for pkg in packages:
        r = results[pkg.name]
        before, after = r.before, r.after
        advisories = "<br>".join(f"• {a}" for a in pkg.advisories)
        is_direct = normalize_name(pkg.name) in direct_deps
        label = "direct" if is_direct else "transitive"

        needs = pkg.fixed or "unknown"
        was_upgraded = after != "unknown" and before != after

        # Fixed if: version meets the known fix, OR fix is unknown but we upgraded to latest
        is_fixed = after != "unknown" and (
            (pkg.fixed is not None and parse_version(after) >= parse_version(pkg.fixed))
            or (pkg.fixed is None and was_upgraded)
        )

        if is_fixed:
            row = f"| {pkg.name} | {before} → {after} | {needs} | {advisories} |"
            (upgraded_direct if is_direct else upgraded_transitive).append(row)
            if r.collateral:
                (collateral_direct if is_direct else collateral_transitive).append(
                    _render_collateral(pkg.name, r.collateral)
                )
            print(f"  ✅ {pkg.name} ({label}) {before} → {after}")
        else:
            version = f"{before} → {after}" if was_upgraded else before
            row = f"| {pkg.name} | {version} | {needs} | {advisories} |"
            (not_upgraded_direct if is_direct else not_upgraded_transitive).append(row)
            print(f"  ⚠️  {pkg.name} ({label}) stuck at {after} — needs {needs}")

    sections: list[str] = []

    sections.append("## Direct dependencies\n")
    sections.append("### Upgraded\n")
    sections.extend(_render_table(upgraded_direct, "No packages were upgraded."))
    for block in collateral_direct:
        sections.extend(block)
    if not_upgraded_direct:
        sections.append("\n### Not upgraded\n")
        sections.extend(_render_table(not_upgraded_direct))

    sections.append("\n## Transitive dependencies\n")
    sections.append("### Upgraded\n")
    sections.extend(_render_table(upgraded_transitive, "No packages were upgraded."))
    for block in collateral_transitive:
        sections.extend(block)
    if not_upgraded_transitive:
        sections.append("\n### Not upgraded\n")
        sections.extend(_render_table(not_upgraded_transitive))

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Git / PR
# ---------------------------------------------------------------------------

def create_or_update_pr(pr_body: str, branch_name: str, pr_title: str) -> None:
    """Commit changes to uv.lock and open or update a PR."""
    diff = git("diff", "uv.lock")
    if not diff.strip():
        print("No lockfile changes — all packages may be constrained.")
        return

    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "github-actions[bot]@users.noreply.github.com")

    # Check for existing PR
    existing = gh(
        "pr", "list",
        "--head", branch_name,
        "--state", "open",
        "--json", "number",
        "--jq", ".[0].number",
    ).strip()

    git("checkout", "-B", branch_name)
    git("add", "uv.lock")
    git("commit", "-m", "fix: upgrade vulnerable dependencies")
    run(["git", "push", "origin", branch_name, "--force"])

    if existing:
        gh("pr", "edit", existing, "--body", pr_body)
        print(f"Updated PR #{existing}")
    else:
        gh("pr", "create", "--title", pr_title, "--body", pr_body)
        print("Created new PR")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    branch_name = os.environ.get("INPUT_BRANCH_NAME", "security/dependency-updates")
    pr_title = os.environ.get("INPUT_PR_TITLE", "Security: upgrade vulnerable dependencies")
    lockfile = Path("uv.lock")
    pyproject = Path("pyproject.toml")

    packages = fetch_alerts(repo)
    print(f"Packages with open alerts: {len(packages)}")

    if not packages:
        print("No open alerts — nothing to do.")
        return

    direct_deps = get_direct_dependencies(pyproject)
    versions = upgrade_packages(packages, lockfile)
    pr_body = build_pr_body(packages, versions, direct_deps)
    create_or_update_pr(pr_body, branch_name, pr_title)


if __name__ == "__main__":
    main()
