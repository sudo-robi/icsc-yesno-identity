# Testing — enforced (from everything-claude-code/rules/testing.md)
Minimum 90% coverage (CI gate `--cov-fail-under=90`). Types: unit + integration + attack (security) tests.
`pytest -q --cov=shared --cov=issuer --cov=verifier --cov-fail-under=80`
Agents: tdd-guide for new features, e2e-runner for shop flow.
