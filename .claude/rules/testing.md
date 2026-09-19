# Testing — enforced (from everything-claude-code/rules/testing.md)
Minimum 80% coverage. Types: unit + integration + attack (security) tests.
TDD: test first RED, minimal impl GREEN, refactor, verify coverage.
`pytest -q --cov=shared --cov=issuer --cov=verifier --cov-fail-under=80`
Agents: tdd-guide for new features, e2e-runner for shop flow.
