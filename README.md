# LinkedIn Buddy

LinkedIn Buddy is a small Node.js dashboard for testing LinkedIn OAuth 2.0 and checking which LinkedIn member and organization endpoints your app can actually use. It now includes an app-level login gate, so the dashboard itself is protected before anyone can start the LinkedIn OAuth flow.

## What it does

- Starts an Express server
- Requires an app login before the dashboard or API can be used
- Redirects you to LinkedIn OAuth
- Exchanges the authorization code for an access token
- Stores the token locally in `data/token-store.json`
- Tests supported member and organization endpoints
- Lets you publish or draft text-only LinkedIn page posts for approved organizations
- Provides a browser UI for session state, page metrics, and test actions

## Install

```bash
npm install
```

## Configure `.env`

Copy `.env.example` to `.env` and fill in real values:

```env
APP_LOGIN_USERNAME=admin
APP_LOGIN_PASSWORD=change_this_before_deploy
APP_SESSION_SECRET=replace_with_a_long_random_secret
APP_SESSION_DURATION_HOURS=12
APP_COOKIE_SECURE=true
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret
LINKEDIN_REDIRECT_URI=https://linkedin-buddy.aiiq.uk/callback
LINKEDIN_VERSION=202506
LINKEDIN_SCOPES=rw_organization_admin,r_organization_social,w_organization_social
PORT=3107
```

Do not commit `.env`.

## LinkedIn app setup

In the LinkedIn Developer Portal, configure this exact redirect URI:

```text
https://linkedin-buddy.aiiq.uk/callback
```

If that value does not exactly match `LINKEDIN_REDIRECT_URI`, OAuth will fail.

## Run

```bash
npm start
```

Then open:

```text
http://localhost:3107/
```

You will see the app login page first. After signing in, use the LinkedIn login button inside the dashboard.

## Docker

Build:

```bash
docker build -t linkedin-buddy .
```

Run:

```bash
docker run --rm --name linkedin-buddy --env-file .env -v ${PWD}/data:/app/data -p 3107:3107 linkedin-buddy
```

## Routes

- `GET /`
  - Protected dashboard
- `GET /login`
  - App login form
- `POST /login`
  - Creates the protected app session
- `POST /app/logout`
  - Clears the app session
- `GET /auth/linkedin`
  - Starts LinkedIn OAuth
- `GET /callback`
  - Completes LinkedIn OAuth and saves the token
- `GET /api/session`
  - Returns saved session metadata
- `GET /api/test/all`
  - Runs the full capability check
- `GET /api/test/member`
  - Tests OIDC member profile
- `GET /api/test/lite-profile`
  - Tests legacy lite profile
- `GET /api/test/email`
  - Tests legacy email access
- `GET /api/test/org-acls`
  - Tests organization admin ACLs
- `GET /api/test/create-post?organizationUrn=urn:li:organization:123456`
  - Attempts a draft organization post
- `POST /api/posts`
  - Creates a LinkedIn organization post
- `POST /api/logout`
  - Removes the saved LinkedIn token and cached results
- `GET /health`
  - Health/config probe for deployment checks

## VPS deployment

For `linkedin-buddy.aiiq.uk`:

- Point the subdomain DNS to your VPS
- Run the app with the production `.env` on the VPS
- Keep `.env` out of git
- Terminate HTTPS at Nginx or Caddy
- Proxy the subdomain to this app on `127.0.0.1:3107`
- Keep `APP_COOKIE_SECURE=true` in production
- Keep the LinkedIn redirect URI set to `https://linkedin-buddy.aiiq.uk/callback`

For the exact confirmed VPS update procedure for this project, see [DEPLOYMENT.md](./DEPLOYMENT.md).

Example Nginx block:

```nginx
server {
    server_name linkedin-buddy.aiiq.uk;

    location / {
        proxy_pass http://127.0.0.1:3107;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## What this app cannot do

- It cannot retrieve your LinkedIn connections list through the normal self-serve API flow.
- It cannot fetch detailed profile data for your connections through the normal self-serve API flow.
- It does not include multi-user accounts, a database, or password reset flows.

## Notes

- `data/` is ignored by git so cached tokens are not published
- The dashboard login is controlled entirely by env vars
- This is still a lightweight utility app, not a full SaaS auth system
