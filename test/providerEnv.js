// Provider environment helpers for switching between mock and live IdPs
// LIVE_IDP=1 activates live mode; PROVIDER identifies the external provider (e.g. auth0, github)

function live() {
  return process.env.LIVE_IDP === '1';
}

function provider() {
  return (process.env.PROVIDER || 'mock').toLowerCase();
}

function isOIDC() {
  // GitHub is pure OAuth 2.0 (no standard id_token) so treat it as non-OIDC
  return !['github'].includes(provider());
}

module.exports = { live, provider, isOIDC };
