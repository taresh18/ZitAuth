import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import pino from 'pino';

const projectRoot = path.resolve(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..'));
const logsDir = path.join(projectRoot, 'logs');
const logFilePath = path.join(logsDir, 'app.log');

if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

let loggerInstance = null;
export function getLogger(name = 'zitauth.node') {
  if (!loggerInstance) {
    const stream = fs.createWriteStream(logFilePath, { flags: 'a', encoding: 'utf8' });
    // Strip time, pid, hostname by customizing base and timestamp
    loggerInstance = pino({ level: 'info', base: { name }, timestamp: false }, stream);
  }
  return loggerInstance;
}

function base64UrlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function generateState() {
  return base64UrlEncode(crypto.randomBytes(32));
}

export function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(64));
}

export function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256').update(Buffer.from(codeVerifier, 'ascii')).digest();
  return base64UrlEncode(hash);
}

export function getKeyFromJwks(jwks, kid) {
  return (jwks?.keys || []).find(k => k.kid === kid);
}