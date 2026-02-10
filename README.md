# Github Actions

Reusable Github Actions workflows for Python projects.

## Workflows

### pytest-uv

Runs tests with pytest using uv.

### pre-commit-uv

Runs pre-commit hooks using uv and [pre-commit-uv](https://github.com/tox-dev/pre-commit-uv).

### prek

Runs [prek](https://github.com/j178/prek) hooks using the [prek-action](https://github.com/j178/prek-action). prek is a fast, Rust-based drop-in replacement for pre-commit.

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

To pass all secrets to called workflow use `secrets: inherit`.

## References

- [Avoiding duplication](https://docs.github.com/en/actions/concepts/workflows-and-actions/avoiding-duplication)
- [Reuse workflows](https://docs.github.com/en/actions/how-tos/sharing-automations/reuse-workflows)
- [Reusable workflows reference](https://docs.github.com/en/actions/reference/reusable-workflows-reference)
- [Allowing access to Github Actions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-access-to-components-in-a-private-repository)
