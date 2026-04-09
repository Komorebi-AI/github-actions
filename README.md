# Github Actions

Reusable Github Actions workflows and composite actions for Python projects.

## Workflows

### pytest-uv

Runs tests with pytest using uv.

### pre-commit-uv

Runs pre-commit hooks using uv and [pre-commit-uv](https://github.com/tox-dev/pre-commit-uv).

### prek

Runs [prek](https://github.com/j178/prek) hooks using the [prek-action](https://github.com/j178/prek-action). prek is a fast, Rust-based drop-in replacement for pre-commit.

### transitive-security-updates (reusable workflow)

Automatically upgrades vulnerable transitive dependencies in `uv.lock`. Fills the gap left by tools like Renovate, which can only bump direct dependencies declared in `pyproject.toml`. This workflow reads GitHub Dependabot alerts and runs `uv lock --upgrade-package` for each vulnerable package, then opens (or updates) a single PR with a detailed description of what was upgraded and what couldn't be.

**Prerequisites:**
- [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts) must be enabled on the calling repository
- A GitHub PAT (classic) with `repo` scope is required (the default `GITHUB_TOKEN` cannot read Dependabot alerts)

## Actions

### transitive-security-updates (composite action)

Same functionality as the reusable workflow above, but implemented as a [composite action](https://docs.github.com/en/actions/sharing-automations/creating-actions/creating-a-composite-action) with a standalone Python script. Use this if you prefer step-level composition over job-level reuse.

## Usage

Simplest example. Python version is read from `.python-version` file and `uv` is set to the latest version:

```yaml
jobs:
  pytest:
    uses: Komorebi-AI/github-actions/.github/workflows/pytest-uv.yml@main
```

More complex example, passing arguments:

```yaml
jobs:
  pytest:
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    uses: Komorebi-AI/github-actions/.github/workflows/pytest-uv.yml@main
    with:
      uv-version: 0.8.0
      python-version: ${{ matrix.python-version }}
      debug-enabled: ${{ github.event_name == 'workflow_dispatch' && inputs.debug_enabled }}
    secrets:
      codecov-token: ${{ secrets.CODECOV_TOKEN }}
      ssh-private-key: ${{ secrets.SSH_PRIVATE_KEY }}
```

prek example. By default runs hooks on all files (`--all-files`). To run only on changed files in a PR, pass `--from-ref` and `--to-ref` via `prek-args`:

```yaml
jobs:
  prek:
    uses: Komorebi-AI/github-actions/.github/workflows/prek.yml@main
    with:
      prek-args: --from-ref ${{ github.event.pull_request.base.sha }} --to-ref ${{ github.event.pull_request.head.sha }}
```

Transitive security updates example. The calling workflow provides the schedule and triggers, and passes a PAT with `repo` scope:

```yaml
name: Transitive Security Updates

on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch:

jobs:
  security:
    uses: Komorebi-AI/github-actions/.github/workflows/transitive-security-updates.yml@main
    secrets:
      token: ${{ secrets.RENOVATE_TOKEN }}
```

With all options:

```yaml
jobs:
  security:
    uses: Komorebi-AI/github-actions/.github/workflows/transitive-security-updates.yml@main
    with:
      uv-version: 0.8.0
      branch-name: security/transitive-updates
      pr-title: "Security: upgrade vulnerable transitive dependencies"
      debug-enabled: ${{ github.event_name == 'workflow_dispatch' && inputs.debug_enabled }}
    secrets:
      token: ${{ secrets.RENOVATE_TOKEN }}
      ssh-private-key: ${{ secrets.SSH_PRIVATE_KEY }}
```

Transitive security updates as a composite action. The caller defines the job and checkout, and uses the action at the step level:

```yaml
name: Transitive Security Updates

on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
          token: ${{ secrets.RENOVATE_TOKEN }}
      - uses: Komorebi-AI/github-actions/transitive-security-updates@main
        with:
          token: ${{ secrets.RENOVATE_TOKEN }}
```

See other usage examples in the [Komorebi-AI/python-template](https://github.com/Komorebi-AI/python-template) repository:

- [prek-main.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/prek-main.yml)
- [prek-pr.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/prek-pr.yml)
- [pytest.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/pytest.yml)

## Common inputs

All inputs are optional, these are the default values:

- `uv-version`: use latest version
- `python-version`: look at `.python-version` or `pyproject.toml` file
- `debug-enabled`: false

## Secrets

Secrets are also optional:

- if `codecov-token` is set coverage will be computed and uploaded to Codecov
- if `ssh-private-key` is set dependencies can be installed from Github repositories inside the Komorebi-AI organization using SSH (via the [ssh-agent](https://github.com/webfactory/ssh-agent) Github Action)
- `token` is **required** for `transitive-security-updates` — a GitHub PAT (classic) with `repo` scope, used to read Dependabot alerts, push branches, and create/update PRs

To pass all secrets to called workflow use `secrets: inherit`.

## References

- [Avoiding duplication](https://docs.github.com/en/actions/concepts/workflows-and-actions/avoiding-duplication)
- [Reuse workflows](https://docs.github.com/en/actions/how-tos/sharing-automations/reuse-workflows)
- [Reusable workflows reference](https://docs.github.com/en/actions/reference/reusable-workflows-reference)
- [Allowing access to Github Actions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-access-to-components-in-a-private-repository)
