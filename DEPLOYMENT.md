# Deployment

This project is deployed on the VPS with Docker, behind Caddy.

These values are confirmed for the current production setup:

- Host app directory: `/var/www/linkedin-buddy`
- Container name: `linkedin-buddy`
- Image name: `linkedin-buddy`
- Internal app port: `3107`
- Host bind: `127.0.0.1:3107:3107`
- Public domain: `https://linkedin-buddy.aiiq.uk`
- Persistent data directory: `/var/www/linkedin-buddy/data`
- Persistent token store: `/var/www/linkedin-buddy/data/token-store.json`

## Production env

The production `.env` file lives in:

```text
/var/www/linkedin-buddy/.env
```

Required values:

```env
APP_LOGIN_USERNAME=...
APP_LOGIN_PASSWORD=...
APP_SESSION_SECRET=...
APP_SESSION_DURATION_HOURS=12
APP_COOKIE_SECURE=true
LINKEDIN_CLIENT_ID=...
LINKEDIN_CLIENT_SECRET=...
LINKEDIN_REDIRECT_URI=https://linkedin-buddy.aiiq.uk/callback
LINKEDIN_VERSION=202506
LINKEDIN_SCOPES=rw_organization_admin,r_organization_social,w_organization_social
PORT=3107
```

Do not commit `.env`.

## Current runtime model

The app is deployed with raw `docker run`, not Docker Compose.

Current expected container start command:

```bash
docker run -d \
  --name linkedin-buddy \
  --restart unless-stopped \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  -p 127.0.0.1:3107:3107 \
  linkedin-buddy
```

## Standard update procedure

Run these commands on the VPS exactly:

```bash
cd /var/www/linkedin-buddy
git fetch origin
git checkout main
git pull --ff-only origin main
docker build -t linkedin-buddy .
docker stop linkedin-buddy || true
docker rm linkedin-buddy || true
docker run -d \
  --name linkedin-buddy \
  --restart unless-stopped \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  -p 127.0.0.1:3107:3107 \
  linkedin-buddy
```

## Post-update verification

After deploying, run:

```bash
cd /var/www/linkedin-buddy
git rev-parse HEAD
git log --oneline -1
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" | grep linkedin-buddy
docker logs --tail 100 linkedin-buddy
curl http://127.0.0.1:3107/health
curl -I https://linkedin-buddy.aiiq.uk
```

Expected behavior:

- `git rev-parse HEAD` matches the latest deployed commit
- `docker ps` shows `linkedin-buddy` running
- `docker logs` shows:

```text
LinkedIn capability explorer listening on http://localhost:3107
```

- `curl http://127.0.0.1:3107/health` returns JSON with `"ok": true`

## Rollout notes

- The app stores LinkedIn token and cached results in `data/token-store.json`
- Rebuilding the container does not remove token/history data because `data/` is mounted from the host
- Do not delete `/var/www/linkedin-buddy/data` unless you intentionally want to remove saved token and cached results
- If `curl` fails immediately after `docker run`, wait a few seconds and retry; the container may still be starting

## Useful diagnostics

Check container status:

```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
docker ps -a | grep linkedin-buddy
docker inspect linkedin-buddy --format 'Status={{.State.Status}} ExitCode={{.State.ExitCode}} Error={{.State.Error}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}}'
```

Check logs:

```bash
docker logs --tail 200 linkedin-buddy
```

Check the production env file:

```bash
cd /var/www/linkedin-buddy
ls -la .env
sed -n '1,120p' .env
```

Run the image interactively to expose startup errors directly:

```bash
cd /var/www/linkedin-buddy
docker run --rm --env-file .env linkedin-buddy
```

## Reverse proxy note

This app is served publicly through Caddy and listens only on loopback from Docker:

```text
127.0.0.1:3107 -> container port 3107
```

The production LinkedIn redirect URI must remain:

```text
https://linkedin-buddy.aiiq.uk/callback
```
