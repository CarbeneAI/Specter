# Specter Deployment Guide

## Running as a systemd Service

### 1. Update the service file

Edit `specter.service` and replace placeholders:

```bash
# Replace YOUR_USERNAME with your actual username
# Replace /path/to/Specter with the actual path
sed -i 's/YOUR_USERNAME/youractualuser/g' specter.service
sed -i 's|/path/to/Specter|/home/youractualuser/Specter|g' specter.service
```

Or edit it manually - the key fields are:

```ini
User=youractualuser
Group=youractualuser
WorkingDirectory=/home/youractualuser/Specter
ExecStart=/home/youractualuser/Specter/manage.sh start
ExecStop=/home/youractualuser/Specter/manage.sh stop
Environment="HOME=/home/youractualuser"
Environment="PATH=/home/youractualuser/.bun/bin:/usr/local/bin:/usr/bin:/bin"
```

### 2. Load environment from .env

Uncomment and update:
```ini
EnvironmentFile=/home/youractualuser/Specter/.env
```

### 3. Install and enable

```bash
# Copy to systemd
sudo cp specter.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable specter

# Start now
sudo systemctl start specter

# Check status
sudo systemctl status specter

# View logs
journalctl -u specter -f
```

## Reverse Proxy with Nginx

To expose Specter at a domain name with HTTPS:

```nginx
# /etc/nginx/sites-available/specter
server {
    listen 443 ssl;
    server_name specter.example.com;

    ssl_certificate /etc/letsencrypt/live/specter.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/specter.example.com/privkey.pem;

    # Client (Vue app)
    location / {
        proxy_pass http://localhost:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name specter-api.example.com;

    # API + WebSocket
    location / {
        proxy_pass http://localhost:4001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Then update your `.env`:
```bash
VITE_API_URL=https://specter-api.example.com
VITE_WS_URL=wss://specter-api.example.com/stream
```

## Reverse Proxy with Traefik

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
          - url: "http://localhost:5173"

    specter-api:
      loadBalancer:
        servers:
          - url: "http://localhost:4001"
```

## Building for Production

The client can be built as static files for serving via nginx directly:

```bash
cd apps/client
bun run build
# Output in apps/client/dist/
```

Serve the `dist/` directory with nginx and point `VITE_API_URL`/`VITE_WS_URL` to your production API server before building.

## Security Considerations

- Specter does not include authentication. **Do not expose it to the public internet** without a reverse proxy with authentication (e.g., Authelia, Authentik, or HTTP basic auth).
- The suppression feature executes SSH commands - ensure the SSH user has minimal required permissions.
- Store your `.env` file with restrictive permissions: `chmod 600 .env`
- Rotate your Anthropic API key periodically.
- The Wazuh password is transmitted to the server - use HTTPS in production.
