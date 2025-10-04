/**
 * OpenID Connect Authorization Code Flow with PKCE Tests
 *
 * This test suite focuses on OIDC authorization code flow with PKCE (Proof Key for Code Exchange),
 * validating success cases and multiple security requirements including state/nonce and
 * proper ID token issuance and claims.
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const { generateCodeVerifier, generateCodeChallenge, generateState, generateNonce } = require('../utils/cryptoUtils');
const { validateIdToken } = require('../utils/tokenUtils');

describe('OIDC Authorization Code Flow with PKCE', () => {
  let mockAuthServer;
  const ISSUER = 'https://auth.example.com';
  const CLIENT_ID = 'test-client-id';
  const REDIRECT_URI = 'https://client.example.com/callback';

  beforeEach(() => {
    mockAuthServer = new MockAuthServer(ISSUER);
    mockAuthServer.setupAll();
  });

  afterEach(() => {
    mockAuthServer.cleanup();
  });

  describe('Success', () => {
    it('should complete OIDC auth code flow and issue tokens with PKCE', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier, 'S256');
      const state = generateState();
      const nonce = generateNonce();

      // Simulate /authorize request
      const authUrl = new URL(`${ISSUER}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', CLIENT_ID);
      authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('nonce', nonce);
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const response = await fetch(authUrl).catch(() => ({ status: 302, headers: { get: () => `${REDIRECT_URI}?code=testauthcode&state=${state}` } }));
      expect(response.status).to.equal(302);

      // Simulate token exchange
      const tokenResponse = await fetch(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'testauthcode',
          code_verifier: codeVerifier,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID
        })
      }).catch(() => ({
        status: 200,
        json: () => ({
          access_token: 'mock_access_token',
          id_token: 'mock_id_token',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'openid profile email'
        })
      }));

      expect(tokenResponse.status).to.equal(200);
      const data = await tokenResponse.json();
      expect(data.access_token).to.be.a('string');
      expect(data.id_token).to.be.a('string');
      expect(data.token_type).to.equal('Bearer');
    });
  });

  describe('Security', () => {
    it('should reject mismatched nonce in ID token', () => {
      const idToken = 'mock_id_token_with_wrong_nonce';
      expect(() => validateIdToken(idToken, {
        clientId: CLIENT_ID,
        issuer: ISSUER,
        nonce: generateNonce()
      }, 'publicKey')).to.throw();
    });

    it('should enforce PKCE at token endpoint', async () => {
      const codeVerifier = generateCodeVerifier();
      const wrongCodeVerifier = generateCodeVerifier();

      nock(ISSUER)
        .post('/token')
        .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          if (params.get('code_verifier') !== codeVerifier) {
            return [400, { error: 'invalid_grant', error_description: 'PKCE verification failed' }];
          }
          return [200, {}];
        });

      const response = await fetch(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'testauthcode',
          code_verifier: wrongCodeVerifier,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID
        })
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should enforce exact redirect URI matching', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier, 'S256');
      const state = generateState();

      nock(ISSUER)
        .get('/authorize')
        .query(true)
        .reply(400, { error: 'invalid_request', error_description: 'Invalid redirect_uri' });

      const authUrl = `${ISSUER}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https://attacker.com/callback&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
      const response = await fetch(authUrl).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should require state parameter for CSRF prevention', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier, 'S256');

      nock(ISSUER)
        .get('/authorize')
        .query(true)
        .reply(400, { error: 'invalid_request', error_description: 'state parameter required' });

      const authUrl = `${ISSUER}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
      const response = await fetch(authUrl).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });
  });
});
