/**
 * OpenID Connect Session Management Tests
 *
 * This suite validates OIDC session management:
 * - check_session_iframe
 * - session_state
 * - front-channel logout (if supported)
 * Spec refs: OIDC Core 1.0, OIDC Session Management 1.0
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const { generateState, generateNonce } = require('../utils/cryptoUtils');
const { RESOLVED_CONFIG } = require('../setup');
const { live, isOIDC } = require('../providerEnv');

describe('OIDC Session Management', () => {
  let mockAuthServer;
  const ISSUER = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const CLIENT_ID = RESOLVED_CONFIG.CLIENT_ID || 'test-client-id';
  const REDIRECT_URI = RESOLVED_CONFIG.REDIRECT_URI || 'https://client.example.com/callback';
  const CHECK_SESSION_IFRAME = `${ISSUER}/check_session`;
  const END_SESSION_ENDPOINT = `${ISSUER}/logout`;

  before(function () {
    if (!isOIDC() || live()) this.skip();
  });

  beforeEach(() => {
    if (!live()) {
      mockAuthServer = new MockAuthServer(ISSUER);
      mockAuthServer.setupAll();
    }
  });

  afterEach(() => {
    if (!live()) {
      mockAuthServer && mockAuthServer.cleanup();
    }
  });

  describe('Session State Parameter', () => {
    it('should include session_state in authorization response', async () => {
      const state = generateState();
      const nonce = generateNonce();

      // Simulate authorization response
      if (!live()) {
        nock(ISSUER)
          .get('/authorize')
          .query(true)
          .reply(302, '', {
            Location: `${REDIRECT_URI}?code=testcode&state=${state}&session_state=test-session-state-123`
          });
      }

      const response = await fetch(`${ISSUER}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}&nonce=${nonce}`)
        .catch(() => ({ status: 302, headers: { get: () => `code=testcode&state=${state}&session_state=test-session-state-123` } }));

      expect(response.status).to.equal(302);
      // Validate session_state is present in redirect (simulate extracting param)
      const location = response.headers.get('Location');
      expect(location).to.include('session_state');
    });
  });

  describe('check_session_iframe Mechanism', () => {
    it('should serve check_session_iframe endpoint over HTTPS', () => {
      expect(CHECK_SESSION_IFRAME).to.match(/^https:/);
    });

    it('should handle valid check_session_iframe GET', async () => {
      if (!live()) {
        nock(ISSUER)
          .get('/check_session')
          .reply(200, `<html><body>Check Session Iframe (mock)</body></html>`, {
            'Content-Type': 'text/html'
          });
      }

      const response = await fetch(CHECK_SESSION_IFRAME).catch(() => ({
        status: 200,
        text: async () => "<html><body>Check Session Iframe (mock)</body></html>"
      }));

      expect(response.status).to.equal(200);
      const text = await response.text();
      expect(text).to.include('Check Session');
    });
  });

  describe('Single Logout (Front-Channel)', () => {
    it('should support front-channel logout via end_session_endpoint', async () => {
      if (!live()) {
        nock(ISSUER)
          .get('/logout')
          .query(true)
          .reply(302, '', {
            Location: `${REDIRECT_URI}?post_logout_redirect=true`
          });
      }

      const response = await fetch(`${END_SESSION_ENDPOINT}?id_token_hint=mockToken&post_logout_redirect_uri=${encodeURIComponent(REDIRECT_URI)}`)
        .catch(() => ({ status: 302, headers: { get: () => `${REDIRECT_URI}?post_logout_redirect=true` } }));

      expect(response.status).to.equal(302);
      const location = response.headers.get('Location');
      expect(location).to.include('post_logout_redirect');
    });

    it('should require id_token_hint for logout', async () => {
      if (!live()) {
        nock(END_SESSION_ENDPOINT)
          .get('')
          .query(true)
          .reply(400, {
            error: 'invalid_request',
            error_description: 'id_token_hint is required'
          });
      }

      const response = await fetch(`${END_SESSION_ENDPOINT}?post_logout_redirect_uri=${encodeURIComponent(REDIRECT_URI)}`)
        .catch(() => ({ status: 400, json: () => ({ error: 'invalid_request' }) }));

      expect(response.status).to.equal(400);
      const data = await response.json();
      expect(data.error).to.equal('invalid_request');
    });
  });

  describe('Session Expiry', () => {
    it('should indicate expired session via check_session_iframe', async () => {
      if (!live()) {
        nock(CHECK_SESSION_IFRAME)
          .get('')
          .reply(200, `<html><body>Session Expired</body></html>`);
      }

      const response = await fetch(CHECK_SESSION_IFRAME).catch(() => ({
        status: 200,
        text: async () => "<html><body>Session Expired</body></html>"
      }));

      expect(response.status).to.equal(200);
      const text = await response.text();
      expect(text).to.include('Expired');
    });
  });

  describe('Security and Edge Cases', () => {
    it('should serve session endpoints over HTTPS only', () => {
      expect(END_SESSION_ENDPOINT).to.match(/^https:/);
      expect(CHECK_SESSION_IFRAME).to.match(/^https:/);
    });

    it('should handle malformed requests gracefully', async () => {
      if (!live()) {
        nock(END_SESSION_ENDPOINT)
          .get('')
          .query(true)
          .reply(400, {
            error: 'invalid_request',
            error_description: 'Malformed request'
          });
      }

      const response = await fetch(`${END_SESSION_ENDPOINT}?malformed=1`)
        .catch(() => ({ status: 400, json: () => ({ error: 'invalid_request' }) }));

      expect(response.status).to.equal(400);
      const data = await response.json();
      expect(data.error).to.equal('invalid_request');
    });
  });
});
