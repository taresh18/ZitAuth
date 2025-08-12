import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { ZitadelClient } from './client.js';
import { getLogger, generateState, generateCodeVerifier, generateCodeChallenge } from './utils.js';

// Load environment
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');
dotenv.config({ path: path.join(repoRoot, '.env') });

const app = express();
const logger = getLogger('zitauth.node.app');
const client = new ZitadelClient();

// Cache `code_verifier` for PKCE, keyed by `state` for the callback exchange
const PKCE_CACHE = new Map(); // state -> code_verifier
const SPA_ORIGIN = process.env.SPA_ORIGIN;

if (!SPA_ORIGIN) {
  logger.error('Missing SPA_ORIGIN environment variable');
  process.exit(1);
}

// Begin OIDC PKCE login: generate state/verifier/challenge and redirect to Zitadel
app.get('/api/v1/login', async (_req, res) => {
  try {
    logger.info('Request received for login');
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    logger.info({ state, codeVerifierPreview: codeVerifier.substring(0, 10), codeChallenge }, 'Generated PKCE values');
    PKCE_CACHE.set(state, codeVerifier);
    const loginUrl = client.getLoginUrl({ state, codeChallenge });
    return res.redirect(loginUrl);
  } catch (e) {
    logger.error(e, 'GET /login failed');
    return res.status(400).json({ detail: `Could not log in. Error: ${e.message || e}` });
  }
});

// Handle Zitadel callback: consume state, exchange code+verifier for tokens, redirect to SPA with access_token hash-fragment
app.get('/api/v1/callback', async (req, res) => {
  const { code, state } = req.query;
  try {
    logger.info('Callback hit after user login, received code from Zitadel');
    const codeVerifier = PKCE_CACHE.get(state);
    PKCE_CACHE.delete(state);
    if (!codeVerifier) {
      return res.status(400).json({ detail: 'Invalid or expired state' });
    }
    const tokens = await client.exchangeCodeForToken(code, codeVerifier);
    const accessToken = tokens?.access_token;
    logger.info('User logged in successfully; returning access token to SPA via redirect');
    const fragment = accessToken ? `#access_token=${accessToken}` : '';
    return res.redirect(`${SPA_ORIGIN}/${fragment}`);
  } catch (e) {
    logger.error(e, 'Login failed during callback processing');
    return res.status(400).json({ detail: `Could not log in. Error: ${e.message || e}` });
  }
});

// Issue M2M token using service-account JWT Bearer Grant
app.get('/api/v1/m2m-token', async (_req, res) => {
  logger.info('Request received for m2m token');
  try {
    const data = await client.getM2MToken();
    return res.json({ access_token: data.access_token });
  } catch (e) {
    logger.error(e, 'GET /auth/m2m-token failed');
    return res.status(500).json({ detail: `Failed to get M2M token: ${e.message || e}` });
  }
});

// Extract Bearer token from Authorization header
function getBearerToken(req) {
  const authHeader = req.header('authorization');
  if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) return null;
  return authHeader.split(' ', 2)[1]?.trim();
}

// Validate JWT via Zitadel JWKS and return decoded claims
app.get('/api/v1/validate', async (req, res) => {
  logger.info('Request received for validate');
  const token = getBearerToken(req);
  if (!token) {
    logger.error('Missing bearer token in authorization header');
    return res.status(400).json({ detail: 'Missing bearer token' });
  }
  try {
    const status = await client.validateToken(token);
    return res.json(status);
  } catch (e) {
    return res.status(401).json({ detail: e.message || String(e) });
  }
});

// Proxy Zitadel userinfo with provided access token
app.get('/api/v1/userinfo', async (req, res) => {
  logger.info('Request received for userinfo');
  const token = getBearerToken(req);
  if (!token) {
    logger.error('Missing bearer token in authorization header');
    return res.status(400).json({ detail: 'Missing bearer token' });
  }
  try {
    const info = await client.getUserinfo(token);
    return res.json({ userinfo: info });
  } catch (e) {
    logger.error(e, 'GET /auth/userinfo failed');
    return res.status(401).json({ detail: `Failed to fetch userinfo. Error: ${e.message || e}` });
  }
});

const port = process.env.PORT ? Number(process.env.PORT) : 8000;
app.listen(port, () => {
  logger.info(`ZitAuth Node app listening on port ${port}`);
});