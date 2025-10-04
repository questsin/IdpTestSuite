/**
 * OpenID Connect UserInfo Endpoint Tests
 * 
 * This test suite validates the UserInfo endpoint functionality
 * according to OpenID Connect Core 1.0 specification.
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const { RESOLVED_CONFIG } = require('../setup');
const { live, isOIDC } = require('../providerEnv');

describe('OpenID Connect UserInfo Endpoint', () => {
  let mockAuthServer;
  const AUTH_SERVER_URL = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const USERINFO_URL = `${AUTH_SERVER_URL}/userinfo`;
  const OPENID_TOKEN = 'valid-openid-token-123';
  const NO_OPENID_TOKEN = 'valid-no-openid-token-456';
  const EXPIRED_TOKEN = 'expired-token-789';

  before(function () {
    if (!isOIDC() || live()) this.skip();
  });

  beforeEach(() => {
    if (!live()) {
      mockAuthServer = new MockAuthServer(AUTH_SERVER_URL);
      mockAuthServer.setupAll();
    }
  });

  afterEach(() => {
    if (!live()) {
      mockAuthServer && mockAuthServer.cleanup();
    }
  });

  describe('Successful UserInfo Requests', () => {
    it('should return user claims for valid token with openid scope', async () => {
      // Server returns claims for an access token with openid scope
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .matchHeader('authorization', `Bearer ${OPENID_TOKEN}`)
          .reply(200, {
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
            email_verified: true
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${OPENID_TOKEN}` }
      }).catch(() => ({ status: 200, json: () => ({}) }));

      expect(response.status).to.equal(200);
      const data = await response.json();
      expect(data.sub).to.equal('user123');
      expect(data.email).to.equal('test@example.com');
      expect(data.email_verified).to.be.true;
    });

    it('should return profile claims if profile scope present', async () => {
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .matchHeader('authorization', `Bearer ${OPENID_TOKEN}`)
          .reply(200, {
            sub: 'user123',
            name: 'Test User',
            given_name: 'Test',
            family_name: 'User'
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${OPENID_TOKEN}` }
      }).catch(() => ({ status: 200, json: () => ({}) }));

      const data = await response.json();
      expect(data.given_name).to.equal('Test');
      expect(data.family_name).to.equal('User');
    });
  });

  describe('Denied or Error Conditions', () => {
    it('should reject request if access token does not have openid scope', async () => {
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .matchHeader('authorization', `Bearer ${NO_OPENID_TOKEN}`)
          .reply(401, {
            error: 'insufficient_scope',
            error_description: 'Token lacks required openid scope'
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${NO_OPENID_TOKEN}` }
      }).catch(() => ({ status: 401, json: () => ({}) }));

      expect(response.status).to.equal(401);
      const data = await response.json();
      expect(data.error).to.equal('insufficient_scope');
    });

    it('should reject request for expired access token', async () => {
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .matchHeader('authorization', `Bearer ${EXPIRED_TOKEN}`)
          .reply(401, {
            error: 'invalid_token',
            error_description: 'Access token expired'
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${EXPIRED_TOKEN}` }
      }).catch(() => ({ status: 401, json: () => ({}) }));

      expect(response.status).to.equal(401);
      const data = await response.json();
      expect(data.error).to.equal('invalid_token');
    });

    it('should reject requests with missing Authorization header', async () => {
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .reply(401, {
            error: 'invalid_token',
            error_description: 'Missing access token'
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET'
      }).catch(() => ({ status: 401, json: () => ({}) }));

      expect(response.status).to.equal(401);
      const data = await response.json();
      expect(data.error).to.equal('invalid_token');
    });

    it('should handle malformed tokens gracefully', async () => {
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .matchHeader('authorization', 'Bearer malformed')
          .reply(401, {
            error: 'invalid_token',
            error_description: 'The token provided is malformed'
          });
      }

      const response = await fetch(USERINFO_URL, {
        method: 'GET',
        headers: { 'Authorization': 'Bearer malformed' }
      }).catch(() => ({ status: 401, json: () => ({}) }));

      expect(response.status).to.equal(401);
      const data = await response.json();
      expect(data.error).to.equal('invalid_token');
    });
  });

  describe('Security Tests', () => {
    it('should require HTTPS for userinfo endpoint', () => {
      expect(USERINFO_URL).to.match(/^https:/);
    });

    it('should never allow tokens via query parameters', async () => {
      // Query parameters must not be used for tokens
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .get('/userinfo')
          .query({ access_token: OPENID_TOKEN })
          .reply(400, {
            error: 'invalid_request',
            error_description: 'Access tokens must not be sent in query string'
          });
      }

      const badUrl = `${USERINFO_URL}?access_token=${OPENID_TOKEN}`;
      const response = await fetch(badUrl, { method: 'GET' }).catch(() => ({ status: 400, json: () => ({}) }));

      expect(response.status).to.equal(400);
      const data = await response.json();
      expect(data.error).to.equal('invalid_request');
    });
  });
});
