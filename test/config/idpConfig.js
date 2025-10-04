// Central configuration loader for mock vs live IdP settings.
// In live mode (LIVE_IDP=1) we prefer environment variables and optionally perform OIDC discovery.
// For discovery we use global fetch (Node 18+) or fall back to dynamic import('node-fetch') if needed.

const { live, provider } = require('../providerEnv');

// Basic safe fetch wrapper (supports Node >=18 with global fetch)
async function httpGetJson(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'Accept': 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

function baseEnvConfig() {
  return {
    issuer: process.env.OIDC_ISSUER,
    authorizationEndpoint: process.env.OIDC_AUTHORIZATION_ENDPOINT,
    tokenEndpoint: process.env.OIDC_TOKEN_ENDPOINT,
    jwksUri: process.env.OIDC_JWKS_URI,
    userInfoEndpoint: process.env.OIDC_USERINFO_ENDPOINT,
    introspectionEndpoint: process.env.OIDC_INTROSPECTION_ENDPOINT,
    endSessionEndpoint: process.env.OIDC_END_SESSION_ENDPOINT,
    registrationEndpoint: process.env.OIDC_REGISTRATION_ENDPOINT,
    clientId: process.env.OIDC_CLIENT_ID || 'test-client-id',
    clientSecret: process.env.OIDC_CLIENT_SECRET || 'test-client-secret',
    redirectUri: process.env.OIDC_REDIRECT_URI || 'https://client.example.com/callback',
    scopes: process.env.OIDC_SCOPES || 'openid profile email',
    audience: process.env.OIDC_AUDIENCE,
    provider: provider(),
    live: live()
  };
}

async function withDiscovery(cfg) {
  if (!cfg.live) return cfg; // mock mode
  if (cfg.authorizationEndpoint && cfg.tokenEndpoint) return cfg; // already supplied
  if (!cfg.issuer) return cfg; // cannot discover
  try {
    const wellKnown = cfg.issuer.replace(/\/?$/, '/') + '.well-known/openid-configuration';
    const doc = await httpGetJson(wellKnown);
    cfg.authorizationEndpoint = cfg.authorizationEndpoint || doc.authorization_endpoint;
    cfg.tokenEndpoint = cfg.tokenEndpoint || doc.token_endpoint;
    cfg.jwksUri = cfg.jwksUri || doc.jwks_uri;
    cfg.userInfoEndpoint = cfg.userInfoEndpoint || doc.userinfo_endpoint;
    cfg.introspectionEndpoint = cfg.introspectionEndpoint || doc.introspection_endpoint;
    cfg.endSessionEndpoint = cfg.endSessionEndpoint || doc.end_session_endpoint || doc.end_session_endpoint_url;
    cfg.registrationEndpoint = cfg.registrationEndpoint || doc.registration_endpoint;
    return cfg;
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('Discovery failed:', e.message);
    return cfg; // Continue without discovery
  }
}

let cachedPromise;
function loadConfig() {
  if (!cachedPromise) {
    cachedPromise = (async () => {
      const cfg = baseEnvConfig();
      return await withDiscovery(cfg);
    })();
  }
  return cachedPromise;
}

module.exports = { loadConfig };
