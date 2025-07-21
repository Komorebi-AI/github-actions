# Github Actions

Use these workflows in another repository:

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

All arguments are optional, these are the default values:

- `uv-version`: use latest version
- `python-version`: look at `.python-version` or `pyproject.toml` file
- `debug-enabled`: false

Secrets are also optional:

- if `codecov-token` is set coverage will be computed and uploaded to Codecov
- if `ssh-private-key` is set dependencies can be installed from Github repositories inside the Komorebi-AI organization (using the [ssh-agent](https://github.com/webfactory/ssh-agent) Github Action)

To pass all secrets to called workflow `secrets: inherit` can be used.

## Documentation

- [Reuse workflows](https://docs.github.com/en/actions/how-tos/sharing-automations/reuse-workflows)
- [Reusable workflows reference](https://docs.github.com/en/actions/reference/reusable-workflows-reference)
- [Allowing access to Github Actions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-access-to-components-in-a-private-repository)
