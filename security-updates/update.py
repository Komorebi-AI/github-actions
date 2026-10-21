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
from datetime import datetime, timedelta, timezone
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
        # Prefer the GHSA advisory page: it always exists for a Dependabot
        # alert, whereas a freshly-assigned CVE is often still RESERVED and
        # returns "CVE ID Not Found" on NVD. Show the CVE as the link text
        # when we have one, since it's the more familiar identifier.
        if self.ghsa:
            text = self.cve or self.ghsa
            return f"[{text}](https://github.com/advisories/{self.ghsa})"
        if self.cve:
            return f"[{self.cve}](https://nvd.nist.gov/vuln/detail/{self.cve})"
        return "unknown advisory"

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

    # Group by normalized package name. GitHub's advisory database reports
    # the same package under inconsistent casing across advisories (e.g.
    # "starlette" and "Starlette"); grouping by the raw name would split it
    # into two packages, each with its own (lower) fix version, and the
    # second upgrade would downgrade what the first one fixed.
    grouped: dict[str, VulnerablePackage] = {}
    for a in alerts:
        name = a["name"]
        key = normalize_name(name)
        fixed = a.get("fixed")
        advisory = Advisory(
            ghsa=a.get("ghsa"),
            cve=a.get("cve"),
            summary=a["summary"],
            severity=a["severity"],
        )
        if key not in grouped:
            grouped[key] = VulnerablePackage(name=normalize_name(name), fixed=fixed)
        else:
            # Keep the highest fix version (None means no known fix)
            if fixed and (
                grouped[key].fixed is None
                or parse_version(fixed) > parse_version(grouped[key].fixed)
            ):
                grouped[key].fixed = fixed
        grouped[key].advisories.append(advisory)

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


# Temporary per-package cooldown exceptions live in pyproject.toml as
# `exclude-newer-package = { pkg = "<timestamp>" }` under [tool.uv], with the
# timestamp just after the fixed release's upload time so only that release
# escapes the cooldown. uv >= 0.11.8 rejects lockfiles whose exceptions are
# not also in pyproject.toml.
# This comment line, directly above that key, lists the entries the bot
# owns, so entries added by hand (e.g. `torch = false`) are never removed.
TEMP_EXCEPTIONS_MARKER = "# security-updates: temporary cooldown exceptions:"
_EXCLUDE_NEWER_PACKAGE_RE = re.compile(r"^exclude-newer-package\s*=\s*\{(?P<body>[^}]*)\}\s*$")


def _tool_uv_section(lines: list[str]) -> tuple[int, int] | None:
    """Return the [start, end) line range of the [tool.uv] table body."""
    for i, line in enumerate(lines):
        if line.strip() == "[tool.uv]":
            end = next(
                (j for j in range(i + 1, len(lines)) if lines[j].lstrip().startswith("[")),
                len(lines),
            )
            return i + 1, end
    return None


def read_temp_exceptions(pyproject: Path) -> set[str]:
    """Packages with a bot-owned cooldown exception in pyproject.toml."""
    if not pyproject.exists():
        return set()
    for line in pyproject.read_text().splitlines():
        if line.startswith(TEMP_EXCEPTIONS_MARKER):
            return {p.strip() for p in line[len(TEMP_EXCEPTIONS_MARKER):].split(",") if p.strip()}
    return set()


def read_exception_cutoff(pkg_name: str, lockfile: Path) -> str | None:
    """Cutoff just after the latest upload of the locked version of *pkg_name*.

    Read from the upload-time of its sdist/wheels in uv.lock. None when the
    package has no upload times (e.g. a git or path source).
    """
    with open(lockfile, "rb") as f:
        data = tomllib.load(f)
    uploads: list[datetime] = []
    for pkg in data.get("package", []):
        if normalize_name(pkg["name"]) != normalize_name(pkg_name):
            continue
        files = [pkg["sdist"]] if "sdist" in pkg else []
        files += pkg.get("wheels", [])
        uploads += [datetime.fromisoformat(f["upload-time"]) for f in files if "upload-time" in f]
    if not uploads:
        return None
    cutoff = max(uploads).astimezone(timezone.utc) + timedelta(seconds=1)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def set_temp_exception(pyproject: Path, pkg_name: str, cutoff: str | None) -> bool:
    """Add (or remove, when *cutoff* is None) a bot-owned cooldown exception.

    Only handles the inline-table form under [tool.uv]. Returns False when
    the file has no [tool.uv] table or uses a form this can't edit safely.
    """
    lines = pyproject.read_text().splitlines()
    section = _tool_uv_section(lines)
    if section is None:
        return False
    start, end = section

    key_idx = next((i for i in range(start, end) if lines[i].startswith("exclude-newer-package")), None)
    entries: dict[str, str] = {}
    if key_idx is not None:
        match = _EXCLUDE_NEWER_PACKAGE_RE.match(lines[key_idx])
        if match is None:
            print(f"  Warning: can't edit exclude-newer-package in {pyproject}: {lines[key_idx]!r}")
            return False
        for item in filter(None, (s.strip() for s in match["body"].split(","))):
            name, _, value = item.partition("=")
            entries[name.strip()] = value.strip()

    owned = read_temp_exceptions(pyproject)
    if cutoff is not None:
        entries[pkg_name] = f'"{cutoff}"'
        owned.add(pkg_name)
    else:
        if pkg_name not in owned:
            return False
        entries.pop(pkg_name, None)
        owned.discard(pkg_name)

    marker_idx = key_idx - 1 if key_idx is not None and lines[key_idx - 1].startswith(TEMP_EXCEPTIONS_MARKER) else None
    new_lines: list[str] = []
    if owned:
        new_lines.append(f"{TEMP_EXCEPTIONS_MARKER} {', '.join(sorted(owned))}")
    if entries:
        body = ", ".join(f"{k} = {v}" for k, v in entries.items())
        new_lines.append(f"exclude-newer-package = {{ {body} }}")

    if key_idx is None:
        # Insert right after `exclude-newer = ...`, or at the top of [tool.uv].
        anchor = next((i for i in range(start, end) if lines[i].startswith("exclude-newer ")), start - 1)
        lines[anchor + 1:anchor + 1] = new_lines
    else:
        first = marker_idx if marker_idx is not None else key_idx
        lines[first:key_idx + 1] = new_lines
    pyproject.write_text("\n".join(lines) + "\n")
    return True


def cleanup_temp_exceptions(pyproject: Path, lockfile: Path, keep: set[str]) -> list[str]:
    """Drop bot-owned exceptions the cooldown no longer needs.

    An exception is no longer needed once removing it and re-locking leaves
    every locked version unchanged (the fixed release has aged past the
    cooldown). Packages in *keep* are left alone. Returns removed names.
    """
    removed: list[str] = []
    for pkg_name in sorted(read_temp_exceptions(pyproject) - keep):
        lock_snapshot, pyproject_snapshot = lockfile.read_bytes(), pyproject.read_bytes()
        versions_before = read_all_versions(lock_snapshot)
        if set_temp_exception(pyproject, pkg_name, None):
            result = run(["uv", "lock"], check=False)
            if result.returncode == 0 and read_all_versions(lockfile.read_bytes()) == versions_before:
                print(f"Removed temporary cooldown exception for {pkg_name}")
                removed.append(pkg_name)
                continue
        lockfile.write_bytes(lock_snapshot)
        pyproject.write_bytes(pyproject_snapshot)
    return removed


def upgrade_packages(
    packages: list[VulnerablePackage], lockfile: Path, pyproject: Path,
) -> tuple[dict[str, UpgradeResult], list[str]]:
    """Run uv lock --upgrade-package for each package.

    When the fix version is known, pin to that version to minimise churn.
    When unknown, upgrade to latest.

    If the fix version is blocked by the exclude-newer cooldown, retry with
    a per-package override and persist it in pyproject.toml as a temporary
    exception scoped to the fixed release.

    Snapshots the lockfile before each attempt and restores it if the
    upgrade fails or produces a broken resolution (e.g. the package
    gets removed instead of upgraded because its dependencies can't be
    satisfied without upgrading other locked packages).

    Returns ({package_name: UpgradeResult}, packages given an exception).
    """
    results: dict[str, UpgradeResult] = {}
    excepted: list[str] = []
    target_names = {normalize_name(p.name) for p in packages}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for pkg in packages:
        before = read_version(pkg.name, lockfile)
        specifier = f"{pkg.name}=={pkg.fixed}" if pkg.fixed else pkg.name
        cmd = ["uv", "lock", "--upgrade-package", specifier]

        snapshot = lockfile.read_bytes()
        pyproject_snapshot = pyproject.read_bytes() if pyproject.exists() else None
        versions_before = read_all_versions(snapshot)

        print(f"Upgrading {pkg.name} (current: {before}, target: {pkg.fixed or 'latest'})...")
        result = run(cmd, check=False)
        after = read_version(pkg.name, lockfile)

        # Validate the upgrade actually produced the expected result.
        # uv can silently produce a broken resolution (e.g. removing the
        # package entirely) when the target version's dependencies conflict
        # with other locked packages.
        def reached_fix(after: str) -> bool:
            return after != "unknown" and parse_version(after) >= parse_version(pkg.fixed)

        if pkg.fixed and (result.returncode != 0 or not reached_fix(after)):
            lockfile.write_bytes(snapshot)
            print(f"  Retrying {pkg.name} with a temporary cooldown exception...")
            result = run([*cmd, "--exclude-newer-package", f"{pkg.name}={now}"], check=False)
            after = read_version(pkg.name, lockfile)
            if result.returncode == 0 and reached_fix(after):
                # Persist the exception in pyproject.toml and re-lock so the
                # lockfile options match the project settings.
                cutoff = read_exception_cutoff(pkg.name, lockfile)
                if cutoff is not None and set_temp_exception(pyproject, pkg.name, cutoff):
                    result = run(["uv", "lock"], check=False)
                    after = read_version(pkg.name, lockfile)
                    if result.returncode == 0 and reached_fix(after):
                        excepted.append(pkg.name)
                else:
                    print(f"  Warning: can't persist a cooldown exception for {pkg.name}")
                    lockfile.write_bytes(snapshot)
                    after = before

        if result.returncode != 0:
            print(f"  Warning: uv lock failed for {pkg.name}: {result.stderr.strip()}")
            lockfile.write_bytes(snapshot)
            if pyproject_snapshot is not None:
                pyproject.write_bytes(pyproject_snapshot)
            results[pkg.name] = UpgradeResult(before=before, after=before)
            continue

        if pkg.fixed:
            upgrade_ok = reached_fix(after)
        else:
            upgrade_ok = after != "unknown" and after != before

        if upgrade_ok:
            versions_after = read_all_versions(lockfile.read_bytes())
            if versions_before == versions_after:
                # No package version actually moved — the only change is
                # metadata (e.g. the per-package exclude-newer timestamp).
                # This happens when the package is already at the fix version
                # but the scanner still flags it. Discard the metadata-only
                # churn so an all-no-op run leaves no diff and opens no PR.
                print(
                    f"  No version change for {pkg.name} — only metadata moved, "
                    f"restoring lockfile"
                )
                lockfile.write_bytes(snapshot)
                if pyproject_snapshot is not None:
                    pyproject.write_bytes(pyproject_snapshot)
                if pkg.name in excepted:
                    excepted.remove(pkg.name)
                results[pkg.name] = UpgradeResult(before=before, after=after)
                continue
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
            if pyproject_snapshot is not None:
                pyproject.write_bytes(pyproject_snapshot)
            if pkg.name in excepted:
                excepted.remove(pkg.name)
            results[pkg.name] = UpgradeResult(before=before, after=before)

    return results, excepted


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

        # Drop phantom rows: the package is already at (or above) the fix
        # version, nothing actually changed, and no other package moved as a
        # result. These come from stale/false-positive advisories that flag a
        # version that is in fact already patched (e.g. urllib3 2.7.0 → 2.7.0).
        # Listing them confuses reviewers, so omit them from the PR body
        # entirely (they don't belong in "Not upgraded" — they're not stuck).
        already_satisfied = (
            pkg.fixed is not None
            and after != "unknown"
            and not was_upgraded
            and not r.collateral
            and parse_version(after) >= parse_version(pkg.fixed)
        )
        if already_satisfied:
            print(f"  ⏭️  {pkg.name} ({label}) already at {after} (needs {needs}) — skipping")
            continue

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
    """Commit changes to uv.lock (and pyproject.toml) and open or update a PR."""
    diff = git("diff", "--", "uv.lock", "pyproject.toml")
    if not diff.strip():
        print(
            "No real package changes (only stale advisories or constrained "
            "packages) and no expired exceptions — skipping PR."
        )
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
    if Path("pyproject.toml").exists():
        git("add", "pyproject.toml")
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

    direct_deps = get_direct_dependencies(pyproject)
    versions, excepted = upgrade_packages(packages, lockfile, pyproject)
    pr_body = build_pr_body(packages, versions, direct_deps)

    # Expired exceptions are removed on every run, even when there are no
    # alerts, so they never outlive the cooldown by more than the PR's review.
    removed = cleanup_temp_exceptions(pyproject, lockfile, keep=set(excepted))
    notes = []
    if excepted:
        notes.append(
            "Temporary cooldown exception (`exclude-newer-package` in pyproject.toml) "
            f"added for: {', '.join(excepted)}. It lets only the fixed release through "
            "the cooldown and is removed automatically once that release is older than "
            "the cooldown."
        )
    if removed:
        notes.append(f"Expired temporary cooldown exceptions removed for: {', '.join(removed)}.")
    if notes:
        pr_body += "\n\n" + "\n\n".join(notes)

    create_or_update_pr(pr_body, branch_name, pr_title)


if __name__ == "__main__":
    main()
