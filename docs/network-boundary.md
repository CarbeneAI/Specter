# Local network boundary and migration

Specter defaults to one local browser origin at `http://127.0.0.1:5173`.
The Bun API binds to `127.0.0.1:4001`; Vite dev and preview bind to
`127.0.0.1:5173`. Node.js 22+ runs Vite (22.22.2 tested); Bun 1.3.14 remains
the API runtime and package manager. The tested Bun Node HTTP compatibility
layer fails to forward a legitimate Vite WebSocket upgrade. Running that same
Vite configuration under Node passes the HTTP and WebSocket fixtures.
The foreground launcher invokes Node explicitly. The existing client scripts
run Vite through its Node shebang, which ordinary `bun run dev` honors. Do not
force Vite into Bun with `bun --bun run dev` or `bun path/to/vite`; the actual
`bun run dev` command is covered by a local stream regression fixture.

This is request admission, not authentication. A client outside a browser can
supply allowed Host and Origin headers. Reported `X-Authentik-*` identity headers
are unverified by Specter. Remote access still requires a firewall and a trusted
authenticated reverse proxy that strips client-supplied identity headers.
TLS trust, provider egress, polling behavior, and process lifecycle are separate.

## Configuration

The launchers source the checkout's root `.env` as trusted shell input. For an
individual backend `bun run dev` session, export that root configuration first.
Vite reads the root `.env` for dev, build, and preview. Existing process variables
have precedence. `VITE_*` settings are public build-time values included in the
browser bundle; rebuild static assets when changing them. Do not put secrets in
`VITE_*` values. The tracked deployed `.env.production` defaults were removed.

| Setting | Default | Contract |
| --- | --- | --- |
| `SPECTER_API_HOST` | `127.0.0.1` | API bind hostname/IP |
| `SPECTER_CLIENT_HOST` | `127.0.0.1` | Vite dev/preview bind hostname/IP |
| `PORT` | `4001` | API port |
| `CLIENT_PORT` | `5173` | Vite dev/preview port |
| `CORS_ALLOWED_ORIGIN` | `http://127.0.0.1:${CLIENT_PORT}` | One exact HTTP(S) browser origin |
| `SPECTER_ALLOWED_HOSTS` | no extra hosts | Comma-separated exact extra hostnames/IPs; IPv6 is bracketed; no wildcard, scheme, path, or port |
| `VITE_API_URL` | `/api` | Optional API base, including a relative or absolute base path |
| `VITE_WS_URL` | current-origin `/stream` | Optional complete WebSocket URL; defaults to `ws:` for HTTP and `wss:` for HTTPS |

Port values must be integers from 0 to 65535; use nonzero ports for deployment.
Port 0 is used only for ephemeral local fixtures. Bind syntax, ports, the origin,
and extra Host values are checked before ingestion starts. An explicit bind does
not automatically allow its hostname. The default Host set is exactly
`localhost`, `127.0.0.1`, and `[::1]`; the request port can vary.

The shared API/Vite HTTP guard rejects unknown or malformed Host values,
foreign/null Origin values, and requests without Origin that explicitly report
`Sec-Fetch-Site: cross-site` or `same-site`. A missing Origin remains allowed for
CLI and n8n callers when Host is allowed. Checks precede route handling, OPTIONS,
and API WebSocket upgrade. A denied socket receives no initial alerts or stats.
Forwarded Host headers do not establish admission.

All four browser callers use `src/lib/endpoints.ts`. Vite proxies only the exact
`/api` path segment, strips that prefix, and forwards `/stream` WebSocket
upgrades. It preserves Host and Origin through both paths so the API can apply
its policy, including upgrades which bypass Vite's HTTP middleware. `/apix` is
not an API proxy route. There is no Origin rewriting or automatic wildcard trust. Vite HMR sockets
use Vite's separate Host/token checks and are disabled in the network fixtures.
`useLedger` resolves relative bases against the page origin and includes
credentials on both list and detail requests.

## Same-origin reverse proxy

Keep the API on loopback when the proxy runs on the same host. For an example
frontend at `https://specter.example.com`, configure:

```sh
CORS_ALLOWED_ORIGIN=https://specter.example.com
SPECTER_ALLOWED_HOSTS=specter.example.com
# Leave VITE_API_URL and VITE_WS_URL unset for same-origin defaults.
```

Serve built `apps/client/dist` assets and route API and stream requests to Bun.
The following Nginx routing fragment must sit behind your configured TLS and
authentication policy; it does not add authentication itself:

```nginx
root /path/to/Specter/apps/client/dist;
location / { try_files $uri $uri/ /index.html; }
location /api/ {
    proxy_pass http://127.0.0.1:4001/;
    proxy_set_header Host $http_host;
}
location = /stream {
    proxy_pass http://127.0.0.1:4001/stream;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Preserve the browser's Origin. For a separate proxy container, loopback refers
to that container: choose an explicit API bind reachable on the private network,
allow the exact incoming Host, and restrict the listening port with the network
firewall. Vite is a development/preview server, not the production static host.

## Split-origin hosting

For a frontend at `https://specter.example.com` and API at
`https://specter-api.example.com`, set these root `.env` values before building:

```sh
CORS_ALLOWED_ORIGIN=https://specter.example.com
SPECTER_ALLOWED_HOSTS=specter.example.com,specter-api.example.com
VITE_API_URL=https://specter-api.example.com
VITE_WS_URL=wss://specter-api.example.com/stream
```

The API proxy routes `/` directly to Bun in this example. If it instead uses a
base path, include that base in both browser overrides and configure the proxy
rewrite explicitly. The API permits one browser origin, including its scheme
and nondefault port. Cookie and authentication policy belong to your proxy.

## Remote n8n

An n8n process on the Specter host can still post without Origin to
`http://127.0.0.1:4001/alerts/ingest`. A remote n8n instance cannot reach the new
loopback default. Prefer an authenticated proxy; if a private interface must be
reachable, explicitly set `SPECTER_API_HOST` to that interface (or intentionally
`0.0.0.0`), add the incoming hostname/IP to `SPECTER_ALLOWED_HOSTS`, and restrict
access with the firewall. Setting a broad bind or an allowed Host alone grants
no identity or authorization. Avoid exposing suppression or ingestion directly
to an untrusted network.

## Offline regression checks

With Bun 1.3.14 and Node 22.22.2 installed:

```sh
(cd apps/server && bun install --frozen-lockfile && bun --no-env-file test && bun run typecheck)
(cd apps/client && bun install && bun --no-env-file test && bun run build)
python3 tests/test_launcher.py LauncherTests ManagerConfigTests
bash -n start-specter.sh manage.sh
shellcheck start-specter.sh
```

On this startup-based branch the server has 90 tests, including four policy
fixtures and five real HTTP/WebSocket child scenarios. The client has 23 tests:
17 existing logic tests, two endpoint resolution tests, one mocked ledger caller,
and actual Vite dev, preview, and `bun run dev` HTTP/WebSocket proxy fixtures. Launcher tests
retain the 12 lifecycle cases and add two Node prerequisite cases (a version command returning 127 and an old version). Four
manager fixtures cover unavailable/failing/old Node version commands and root
configuration/IPv6 status URLs. Availability checks also reject a missing Node executable. Fixtures use
loopback ports and mocked startup/provider/suppression/mute/ledger dependencies;
they do not contact Wazuh, SSH, or AI providers. The existing integration suite
uses disposable ledger/mute/JSONL paths and a guarded fetch stub. A private
combined audit with the Markdown change supplies its frozen client lock and
separately exercises Chromium. These checks do not prove remote deployment or
proxy authentication correctness.

[Vite server proxy options](https://v5.vite.dev/config/server-options) and
[Bun's upgrade compatibility issue](https://github.com/oven-sh/bun/issues/25156)
explain the proxy/runtime constraints behind this boundary.
