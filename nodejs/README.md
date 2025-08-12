## ZitAuth (Node.js) — Zitadel Authentication Wrapper

This is the Node.js port of the ZitAuth service. It exposes the same endpoints and behavior, acting as a centralized gateway over Zitadel for PKCE user login, M2M token issuance, token validation, and userinfo proxy.

### Prerequisites

- Node.js 18+

### Install and Run

From the repo root:

```bash
cd nodejs
npm install

npm run dev
```

The service listens on port `8000` by default.

### Endpoints

- `GET /api/v1/login`: Starts OIDC PKCE login (redirects to Zitadel auth endpoint).
- `GET /api/v1/callback?code&state`: Handles the Zitadel callback, exchanges the code for tokens, and redirects to `SPA_ORIGIN/#access_token=...`.
- `GET /api/v1/m2m-token`: Issues an M2M access token using the configured service account (JWT Bearer Grant).
- `GET /api/v1/validate`: Validates a JWT (via JWKS) and returns decoded claims. Requires `Authorization: Bearer <token>`.
- `GET /api/v1/userinfo`: Proxies to Zitadel userinfo. Requires `Authorization: Bearer <token>`.

