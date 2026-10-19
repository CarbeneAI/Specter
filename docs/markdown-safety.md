# Markdown output safety

Model responses can repeat attacker-controlled alert or threat-feed content.
`ChatPanel.vue` calls `src/lib/markdown.ts` before inserting assistant content
into HTML. The helper parses Markdown with [Marked](https://marked.js.org/)
and sanitizes the result with [DOMPurify](https://github.com/cure53/DOMPurify).
Marked itself does not sanitize HTML.

The allowlist preserves headings, paragraphs, emphasis, lists, tables, code,
blockquotes, and links. Only explicit `http://` and `https://` links retain their
`href`. Relative paths, protocol-relative links, and other schemes lose it.
Images, media, forms, embedded documents, SVG, MathML, styles, event handlers,
and HTML identifiers are excluded. This prevents model-provided image embeds
from fetching tracking or IOC resources. Code examples remain escaped text.
If DOMPurify reports that the browser is unsupported, the helper returns empty
output. No raw HTML fallback is used.

This controls HTML insertion in the documented renderer. It does not determine
whether a finding is correct, whether an HTTP(S) destination is trustworthy, or
whether it is safe to visit an IOC. Links still require analyst judgment.
It does not add authentication, constrain server tools, or establish readiness
for public hosting. Keep self-hosted deployments within their existing trusted
network boundary and review hosted access controls separately.

Do not append HTML to the sanitized result or expand the allowlist without
reviewing the security implications and adding regression cases. Keep DOMPurify
current with its security releases; the client lockfile records the reviewed
dependency versions.

## Offline browser checks

From the repository root:

```bash
cd apps/client
bun install --frozen-lockfile
bunx playwright install chromium
bun --no-env-file run test:markdown
bun --no-env-file test
bun run build
```

Use Bun 1.3.14 and Node.js 22 for the test CLI. The application runtime remains
Bun. Installing dependencies and the browser requires network access; the test
fixtures use synthetic data only. The test command starts an isolated Vite
server on loopback, mounts the real ChatPanel, disables HMR, and blocks browser
requests after fixture loading. It does not start the backend or contact a
model, feed, Wazuh, SSH host, or other integration.

The 7 Chromium tests cover ordinary Markdown, raw HTML and events, encoded
unsafe links, namespace and mutation payloads, resource embeds, changed message
content, and the unsupported-sanitizer path.
The 17 existing client grouping and mute checks run with `bun test`. The client
`bunfig.toml` limits that runner to `src`; browser specs under `tests/markdown`
use the separate Playwright command above. This keeps ordinary Bun test discovery
from executing Playwright hooks under the wrong runner.
These are focused browser regressions and a client build, not a full security
audit or verification across every browser. CI runs the same fixture suite on
Ubuntu. Sanitizer and browser updates still require review.
