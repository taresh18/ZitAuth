import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { URLSearchParams } from 'node:url';
import crypto from 'node:crypto';
import { SignJWT, importJWK, jwtVerify, decodeProtectedHeader } from 'jose';
import { getLogger, getKeyFromJwks } from './utils.js';

const logger = getLogger('zitauth.node.client');

export class ZitadelClient {
  constructor(env = process.env) {
    try {
      // Validate required configuration from environment
      const required = [
        'ZITADEL_DOMAIN',
        'ZITADEL_CLIENT_ID',
        'ZITADEL_REDIRECT_URL',
        'ZITADEL_AUTHORIZATION_ENDPOINT',
        'ZITADEL_TOKEN_ENDPOINT',
        'ZITADEL_JWKS_URI',
        'ZITADEL_USERINFO_ENDPOINT',
        'SERVICE_ACCOUNT_FILE'
      ];
      const missing = required.filter((k) => !env[k]);
      if (missing.length) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
      }

      this.zitadelDomain = env.ZITADEL_DOMAIN;
      this.zitadelClientId = env.ZITADEL_CLIENT_ID;
      this.zitadelRedirectUrl = env.ZITADEL_REDIRECT_URL;
      this.zitadelAuthEndpoint = env.ZITADEL_AUTHORIZATION_ENDPOINT;
      this.zitadelTokenEndpoint = env.ZITADEL_TOKEN_ENDPOINT;
      this.zitadelJwksUrl = env.ZITADEL_JWKS_URI;
      this.zitadelUserinfoUrl = env.ZITADEL_USERINFO_ENDPOINT;
      this.serviceAccountFile = env.SERVICE_ACCOUNT_FILE;
    } catch (e) {
      logger.error(e, 'Environment configuration error');
      throw e;
    }

    // Cache JWKS between validations; refresh on kid miss
    this.jwksCache = null;
  }

  // Construct authorization URL for PKCE flow
  getLoginUrl({ state, codeChallenge }) {
    const params = new URLSearchParams({
      client_id: this.zitadelClientId,
      redirect_uri: this.zitadelRedirectUrl,
      response_type: 'code',
      scope: 'openid email profile',
      prompt: 'login',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });
    const url = `${this.zitadelAuthEndpoint}?${params.toString()}`;
    logger.info({ url }, 'Generated authorize URL with PKCE');
    return url;
  }

  // Exchange authorization code for tokens at the token endpoint
  async exchangeCodeForToken(code, codeVerifier) {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.zitadelRedirectUrl,
      client_id: this.zitadelClientId,
      code_verifier: codeVerifier
    });
    const resp = await fetch(this.zitadelTokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Token exchange failed: ${resp.status} ${text}`);
    }
    const data = await resp.json();
    logger.info('Exchanged code for tokens successfully');
    return data;
  }

  // Load and parse service-account JSON (supports absolute and repo-root-relative paths)
  loadServiceAccountFile() {
    // Resolve file path: allow absolute, repo-root-relative, or cwd-relative
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const repoRoot = path.resolve(__dirname, '..', '..');
    const candidatePaths = [];

    if (path.isAbsolute(this.serviceAccountFile)) {
      candidatePaths.push(this.serviceAccountFile);
    } else {
      candidatePaths.push(path.join(repoRoot, this.serviceAccountFile));
      candidatePaths.push(path.resolve(process.cwd(), this.serviceAccountFile));
    }

    const resolved = candidatePaths.find((p) => fs.existsSync(p));
    if (!resolved) {
      throw new Error(`Service account file not found. Tried: ${candidatePaths.join(', ')}`);
    }
    const content = fs.readFileSync(resolved, 'utf8');
    return JSON.parse(content);
  }

  // Perform JWT Bearer Grant using service-account private key (RS256)
  async getM2MToken() {
    const serviceAccount = this.loadServiceAccountFile();
    const now = Math.floor(Date.now() / 1000);

    const payload = {
      iss: serviceAccount.userId,
      sub: serviceAccount.userId,
      aud: this.zitadelDomain,
      iat: now,
      exp: now + 15 * 60
    };
    const header = {
      alg: 'RS256',
      kid: serviceAccount.keyId
    };

    // Private key expected as PEM string; normalize escaped newlines from JSON
    const privateKeyPem = (serviceAccount.key || serviceAccount.privateKey || '')
      .replace(/\\n/g, '\n')
      .trim();
    if (!privateKeyPem.startsWith('-----BEGIN')) {
      throw new Error('SERVICE_ACCOUNT_FILE key must be a PEM string with BEGIN/END headers');
    }
    const key = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });

    const jwt = await new SignJWT(payload)
      .setProtectedHeader(header)
      .sign(key);

    logger.info({ jwtPreview: jwt.substring(0, 30) }, 'Generated Encoded JWT');

    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      scope: 'openid',
      assertion: jwt
    });
    const resp = await fetch(this.zitadelTokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`M2M token request failed: ${resp.status} ${text}`);
    }
    const data = await resp.json();
    logger.info({ dataPreview: JSON.stringify(data).substring(0, 80) }, 'Fetched M2M access token via service account JWT');
    return data;
  }

  // Validate a JWT using Zitadel JWKS; verify issuer; skip audience like Python
  async validateToken(token) {
    if (!this.jwksCache) {
      const jwksResp = await fetch(this.zitadelJwksUrl);
      if (!jwksResp.ok) throw new Error(`Failed to fetch JWKS: ${jwksResp.status}`);
      this.jwksCache = await jwksResp.json();
    }

    const header = decodeProtectedHeader(token);
    const kid = header.kid;
    const alg = header.alg;
    if (!kid || !alg || alg !== 'RS256') {
      throw new Error("Token header missing required fields 'kid' or 'alg'");
    }

    let jwk = getKeyFromJwks(this.jwksCache, kid);
    if (!jwk) {
      const jwksResp = await fetch(this.zitadelJwksUrl);
      if (!jwksResp.ok) throw new Error(`Failed to refresh JWKS: ${jwksResp.status}`);
      this.jwksCache = await jwksResp.json();
      jwk = getKeyFromJwks(this.jwksCache, kid);
      if (!jwk) throw new Error('Public key not found in JWKS after refresh');
    }

    const key = await importJWK(jwk, alg);
    const { payload } = await jwtVerify(token, key, {
      issuer: this.zitadelDomain,
      algorithms: [alg],
      audience: undefined // disable audience verification to match Python behavior
    });
    return payload;
  }

  // Proxy to Zitadel userinfo with bearer token
  async getUserinfo(accessToken) {
    const resp = await fetch(this.zitadelUserinfoUrl, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Failed to fetch userinfo: ${resp.status} ${text}`);
    }
    return resp.json();
  }
}