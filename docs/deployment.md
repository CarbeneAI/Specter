# Specter Deployment Guide

## Running as a systemd Service

Install Node.js 22+ (22.22.2 tested), Bun, and dependencies, then configure the checkout's `.env` first. The foreground
launcher, `start-specter.sh`, resolves both apps and `.env` relative to itself,
regardless of systemd's working directory. `.env` is sourced as Bash: quote values
containing spaces or shell metacharacters. It must be trusted by the service user.

Bun can be on the service's `PATH`, in that user's `$HOME/.bun/bin`, or in
`$BUN_INSTALL/bin` (set `BUN_INSTALL` in `.env` for a custom installation).
Node must also be on the service `PATH`; it runs Vite to avoid the WebSocket
upgrade failure in the tested Bun 1.3.14 Node HTTP compatibility layer. Ordinary
`bun run dev` honors Vite's Node shebang; do not use `--bun` to force Vite into Bun.
The launcher stops the other child and exits with a failure if either app exits,
including an unexpected successful exit, so `Restart=on-failure` restarts the pair.
A normal `systemctl stop` exits successfully. systemd stops the service's control group.

Choose **one** of the following units for a checkout; running both would compete
for the same ports.

### System service (starts at boot)

Copy `specter.service` to `/etc/systemd/system/specter.service`, then edit the
installed copy. Set `User` and `Group` to the account that owns the checkout,
replace `/path/to/Specter` with its absolute path, and set `HOME` to that account's
actual home directory. Quote the executable path in `ExecStart` for spaces;
`WorkingDirectory` takes the path directly, without quotes, even with spaces.
For example:

```ini
User=youractualuser
Group=youractualuser
WorkingDirectory=/home/youractualuser/Specter
ExecStart="/home/youractualuser/Specter/start-specter.sh"
Environment="HOME=/home/youractualuser"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
```

```bash
sudo cp specter.service /etc/systemd/system/
# Edit /etc/systemd/system/specter.service with the values above before enabling.
sudoedit /etc/systemd/system/specter.service
sudo systemctl daemon-reload
sudo systemctl enable --now specter
sudo systemctl status specter
journalctl -u specter -f
```

### User service (no root required)

`deploy/specter.service` is the user-unit alternative. Its `%h/Specter` paths
refer to `Specter` in your home directory. If your checkout lives elsewhere,
update `WorkingDirectory` and `ExecStart` in the installed copy to its absolute
path, using the quoting rules above. Do not add `User` or `Group` to a user unit.

```bash
mkdir -p ~/.config/systemd/user
cp deploy/specter.service ~/.config/systemd/user/specter.service
# Edit ~/.config/systemd/user/specter.service if the checkout is not ~/Specter.
systemctl --user daemon-reload
systemctl --user enable --now specter
systemctl --user status specter
journalctl --user -u specter -f
```

By default the user manager runs with your login session. To keep the service
running after logout and start it at boot, enable lingering for your account
with `loginctl enable-linger "$USER"` (administrator authorization may be required).

Use `systemctl stop specter` (with `sudo` for the system unit) or
`systemctl --user stop specter` to stop the service. Avoid `manage.sh stop` for
systemd-managed instances: systemd owns their lifecycle and restart policy.

### Launcher regression tests

Run `python3 tests/test_launcher.py LauncherTests ManagerConfigTests` and `bash -n start-specter.sh`
on Linux or macOS. The tests use temporary checkouts and stub Bun and Node processes,
including paths with spaces, startup failures, child exits, and shutdown. They
do not connect to Wazuh, Suricata, SSH, or an AI provider.

On Linux with `systemd-analyze` installed, also run
`python3 tests/test_launcher.py ServiceTemplateTests` to validate both service
templates with a checkout path containing spaces. CI runs launcher tests on
Linux and macOS, and unit validation, server tests/typecheck, and client
tests/build on Linux. The tests do not install or start a systemd service.

## Reverse Proxy with Nginx

The example below uses separate frontend/API origins. For same-origin `/api`
and `/stream` routing and static hosting, follow [the network guide](network-boundary.md).
Both patterns require an authenticated proxy and an exact browser/Host policy.

To route Specter at domain names with HTTPS:

```nginx
# /etc/nginx/sites-available/specter
server {
    listen 443 ssl;
    server_name specter.example.com;

    ssl_certificate /etc/letsencrypt/live/specter.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/specter.example.com/privkey.pem;

    # Client (Vue app)
    location / {
        proxy_pass http://127.0.0.1:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name specter-api.example.com;

    # API + WebSocket
    location / {
        proxy_pass http://127.0.0.1:4001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Then update your `.env`:
```bash
CORS_ALLOWED_ORIGIN=https://specter.example.com
SPECTER_ALLOWED_HOSTS=specter.example.com,specter-api.example.com
VITE_API_URL=https://specter-api.example.com
VITE_WS_URL=wss://specter-api.example.com/stream
```

## Reverse Proxy with Traefik

The same split-origin `.env` settings above apply to this Traefik routing example.
Preserve Host and Origin and configure authentication before remote exposure.

Example Traefik dynamic config:

```yaml
http:
  routers:
    specter-client:
      rule: "Host(`specter.example.com`)"
      service: specter-client
      entryPoints: [websecure]
      tls:
        certResolver: cloudflare

    specter-api:
      rule: "Host(`specter-api.example.com`)"
      service: specter-api
      entryPoints: [websecure]
      tls:
        certResolver: cloudflare

  services:
    specter-client:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:5173"

    specter-api:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:4001"
```

## Building for Production

The client can be built as static files for serving via nginx directly:

```bash
cd apps/client
bun run build
# Output in apps/client/dist/
```

Serve `dist/` with nginx and route `/api/` and `/stream` to the API as described
in [the network guide](network-boundary.md). For split-origin hosting, set the
public `VITE_API_URL`/`VITE_WS_URL` overrides in the root `.env` before building.
The old deployed `.env.production` defaults have been removed.

## Security Considerations

- Specter does not include authentication. **Do not expose it to the public internet** without a reverse proxy with authentication (e.g., Authelia, Authentik, or HTTP basic auth).
- The suppression feature executes SSH commands - ensure the SSH user has minimal required permissions.
- Store your `.env` file with restrictive permissions: `chmod 600 .env`
- Rotate your Anthropic API key periodically.
- The Wazuh password is transmitted to the server - use HTTPS in production.
