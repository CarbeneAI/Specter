# Proposed contributor roadmap

This is a contributor proposal for maintainer discussion, not an adopted release plan. It complements the [product roadmap](README.md#roadmap) with reliability work that can be reviewed and verified in small changes. The maintainer decides scope, ordering, and scheduling.

## Baseline in this contribution

- Launch the server and client from the actual checkout with configurable Bun discovery.
- Stop owned child processes on shutdown and report unexpected child exits as service failures.
- Align system and user service templates with the foreground launcher.
- Check launcher behavior on Ubuntu and macOS, parse rendered service units on Linux, and run server tests/typechecking plus client tests/build.
- Document provider-specific setup, history, and investigation-ledger behavior.

Fixtures substitute local processes for Bun services. They do not prove a systemd boot, a live Wazuh or Suricata connection, or a model response. Current commands and limitations are in [deployment guidance](docs/deployment.md) and [CI](.github/workflows/ci.yml).

## 1. Expand offline integration contracts

Problem: a passing launcher test cannot establish how the application handles unavailable or malformed upstream data.

Proposed approach: add sanitized Wazuh and Suricata fixtures at the application boundaries, then exercise provider-specific request and response handling with mock transports.

Acceptance criteria:

- Fixtures cover successful responses, authentication failures, timeouts, malformed records, and empty results.
- Tests reject unexpected network access and contain no production identifiers or credentials.
- CLI, Anthropic, and Ollama differences are explicit in tests and documentation rather than assumed interchangeable.
- Error states remain distinguishable from an empty or successful analysis.

## 2. Make connection trust explicit

Original baseline concern: the launcher disabled Node TLS certificate verification for the process, which was broader than trusting a particular Wazuh deployment.

Review the separate [Wazuh transport contribution](https://github.com/CarbeneAI/Specter/pull/6), which proposes scoped certificate verification and migration guidance. Retain these acceptance checks when integrating connection-trust changes; this roadmap does not imply that the original broad override remains in every later composition.

Acceptance criteria:

- Tests distinguish trusted certificates, untrusted certificates, and hostname mismatches.
- A custom CA applies only where intended; unrelated outbound requests retain certificate verification.
- Existing self-signed deployments receive explicit migration and rollback instructions.
- Configuration examples and inline comments explain the actual trust boundary.

## 3. Verify service installation in a disposable Linux lab

Problem: parsing a unit file cannot prove startup, shutdown, restart, or logging behavior under a running systemd instance.

Proposed approach: add an opt-in lab procedure for both service templates, using test endpoints and no production accounts.

Acceptance criteria:

- Fresh install, boot, intentional stop, child failure, restart, and uninstall are observed for each template.
- The service leaves unrelated processes and configuration intact.
- Logs identify actionable failures without exposing credentials or alert payloads unnecessarily.
- Results record the commit and environment; default pull-request CI remains isolated and credential-free.

## Contribution standard

Each change should connect a concrete failure to a regression check and an updated user or coding-agent instruction. Record what was exercised and what remains unverified. Any response automation remains a separate design discussion under the project's existing contribution guidance.

Proposed by Ryan Wentzel, [ryanwentzel.me](https://ryanwentzel.me).
