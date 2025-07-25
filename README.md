# Github Actions

## Usage

These workflows can be used in the Github Actions of other repositories.

Simplest example. Python version is read from `.python-version` file and `uv` is set to the latest version:

```{yaml}
jobs:
  pytest:
    uses: Komorebi-AI/github-actions/.github/workflows/pytest-uv.yml@main
```

More complex example, passing arguments:

```{yaml}
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

See other usage examples in the [Komorebi-AI/python-template](https://github.com/Komorebi-AI/python-template) repository:

- [pre-commit-main.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/pre-commit-main.yml)
- [pre-commit-pr.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/pre-commit-pr.yml)
- [pytest.yml](https://github.com/Komorebi-AI/python-template/blob/main/.github/workflows/pytest.yml)

All arguments are optional, these are the default values:

- `uv-version`: use latest version
- `python-version`: look at `.python-version` or `pyproject.toml` file
- `debug-enabled`: false

Secrets are also optional:

- if `codecov-token` is set coverage will be computed and uploaded to Codecov
- if `ssh-private-key` is set dependencies can be installed from Github repositories inside the Komorebi-AI organization using SSH (via the [ssh-agent](https://github.com/webfactory/ssh-agent) Github Action)

To pass all secrets to called workflow use `secrets: inherit`.

## References

- [Avoiding duplication](https://docs.github.com/en/actions/concepts/workflows-and-actions/avoiding-duplication)
- [Reuse workflows](https://docs.github.com/en/actions/how-tos/sharing-automations/reuse-workflows)
- [Reusable workflows reference](https://docs.github.com/en/actions/reference/reusable-workflows-reference)
- [Allowing access to Github Actions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-access-to-components-in-a-private-repository)
