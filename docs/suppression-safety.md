# Suppression input and command safety

Suppression changes upstream detection: Suricata writes `disable.conf` and
reloads rules; Wazuh writes `local_rules.xml` and restarts its manager. Restrict
access to these operations and prefer dashboard mutes for temporary noise.

Previously, Wazuh XML was interpolated into a remote shell heredoc. A delimiter
inside a submitted description, reason, or existing XML could end that heredoc
and make subsequent content shell commands. A multiline reason could also add
extra Suricata SID entries or break the Wazuh XML comment.

The SSH command now contains only fixed operations and shell-quoted configured
paths. New and existing configuration content travels as stdin bytes, including
any heredoc-looking text. Rule descriptions are escaped as XML text. Suricata
uses SSH stdin instead of SCP, so its destination path follows the same quoting
rules as Wazuh. SSH has no pseudo-terminal; Wazuh uses `sudo -n` so a password
prompt fails instead of consuming configuration input.

## Configuration and input constraints

- Rule IDs and optional Suricata SIDs must be strings containing only digits.
- Reasons must be strings of at most 1000 UTF-16 code units. This bounds the
  comment size; use a short operational explanation. Line breaks, control
  characters, invalid XML characters, and `--` are rejected before file reads,
  local writes, or SSH. Blank reasons receive the default explanation.
- Descriptions must be XML-compatible strings. XML metacharacters are escaped;
  valid multiline descriptions are transferred as data.
- Remote paths must be absolute or begin with `~/`, without control characters.
  Only that leading tilde expands, on the remote host. Spaces, apostrophes, and
  shell metacharacters elsewhere are literal filename characters.
- The Suricata SSH account needs write access to its configured file and
  permission to run the existing Docker update/reload commands. The Wazuh SSH
  account needs noninteractive sudo permission to read/write the configured
  rules file and restart `wazuh-manager`. Scope these permissions to the
  deployment's paths and commands.

The operation is not transactional. Suricata updates its local copy before
transferring it; a transfer failure leaves that local SID present, so a retry
reports it as already suppressed. Inspect and reconcile the local and remote
copies before retrying. A write, update, reload, or restart failure returns
`success: false`; a failed restart can leave the file changed without applying
the new detection behavior. Concurrent updates, atomic replacement, backups,
and remote configuration validation remain separate operational work.

## Offline verification

From `apps/server`, using Bun 1.3.14:

```bash
bun install --frozen-lockfile --no-env-file
bun test --no-env-file
bun run --no-env-file typecheck
```

The suppression fixtures call the production suppression and listing functions. Every
`Bun.spawn` is replaced with an in-process stub, and local files live in a
temporary directory. Coverage includes rejection before effects, reason and
description payloads, old heredoc delimiters already in XML, configured path
quoting, nonzero command exits, and the existing partial-failure state. These
checks do not run SSH, Docker, sudo, remote services, or model requests. They
do not establish that a deployment's remote configuration is valid or applied.
One fixture uses a local POSIX shell with a stub sudo function and a local cat
to verify literal path parsing; any files it creates stay in that temporary directory.

The GitHub workflow runs the full server suite and typecheck when server files,
the workflow, or the related setup documentation change. The integration
fixtures use an ephemeral HTTP listener accessed through localhost and mocked external requests;
they do not require a live deployment. `apps/server/bun.lock` records a fresh resolution of the
server's existing development dependencies for frozen installs. Client
dependency resolution is unchanged.

Ryan Wentzel | [ryanwentzel.me](https://ryanwentzel.me)
