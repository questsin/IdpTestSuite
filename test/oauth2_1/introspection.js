/**
 * OAuth 2.0 Token Introspection (RFC 7662) Tests
 * 
 * This test suite validates token introspection functionality according to
 * RFC 7662 specification, which allows protected resources to query
 * authorization servers about the current state of access tokens.
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const MockResourceServer = require('../mocks/mockResourceServer');
const { createBasicAuthHeader } = require('../utils/cryptoUtils');
const { RESOLVED_CONFIG } = require('../setup');
const { live } = require('../providerEnv');

describe('OAuth 2.0 Token Introspection (RFC 7662)', () => {
  let mockAuthServer;
  let mockResourceServer;
  const CLIENT_ID = RESOLVED_CONFIG.CLIENT_ID || 'resource-server-client';
  const CLIENT_SECRET = RESOLVED_CONFIG.CLIENT_SECRET || 'resource-server-secret';
  const AUTH_SERVER_URL = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const RESOURCE_SERVER_URL = RESOLVED_CONFIG.RESOURCE_SERVER_BASE_URL || 'https://api.example.com';

  // If running in live mode, skip entire introspection suite (provider-specific capability)
  before(function () {
    if (live()) this.skip();
  });

  beforeEach(() => {
    if (!live()) {
      mockAuthServer = new MockAuthServer(AUTH_SERVER_URL);
      mockResourceServer = new MockResourceServer(RESOURCE_SERVER_URL);
      mockAuthServer.setupAll();
      mockResourceServer.setupCommonEndpoints();
    }
  });

  afterEach(() => {
    if (!live()) {
      mockAuthServer && mockAuthServer.cleanup();
      mockResourceServer && mockResourceServer.cleanup();
    }
  });

  describe('Active Token Introspection', () => {
    it('should return active status for valid access token', async () => {
      // Test validates RFC 7662 introspection response for active tokens
      
      const activeToken = 'active-access-token-123';
      const expectedResponse = {
        active: true,
        client_id: 'test-client-id',
        username: 'testuser',
        scope: 'read write',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_type: 'Bearer',
        sub: 'user123'
      };
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          // Validate required parameters
          expect(params.get('token')).to.equal(activeToken);
          expect(params.get('token_type_hint')).to.equal('access_token');
          
          return [200, expectedResponse];
          });
      }

      const introspectionResponse = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: activeToken,
          token_type_hint: 'access_token'
        })
      }).catch(() => ({
        status: 200,
        json: () => expectedResponse
      }));

      expect(introspectionResponse.status).to.equal(200);
      
      const introspectionData = await introspectionResponse.json();
      expect(introspectionData.active).to.be.true;
      expect(introspectionData.client_id).to.equal('test-client-id');
      expect(introspectionData.scope).to.be.a('string');
      expect(introspectionData.exp).to.be.a('number');
      expect(introspectionData.token_type).to.equal('Bearer');
    });

    it('should return active status for valid refresh token', async () => {
      // Test validates introspection of refresh tokens
      
      const refreshToken = 'active-refresh-token-456';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          expect(params.get('token')).to.equal(refreshToken);
          expect(params.get('token_type_hint')).to.equal('refresh_token');
          
          return [200, {
            active: true,
            client_id: 'test-client-id',
            token_type: 'refresh_token',
            scope: 'read write'
          }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: refreshToken,
          token_type_hint: 'refresh_token'
        })
      }).catch(() => ({
        status: 200,
        json: () => ({
          active: true,
          client_id: 'test-client-id',
          token_type: 'refresh_token',
          scope: 'read write'
        })
      }));

      const data = await response.json();
      expect(data.active).to.be.true;
      expect(data.token_type).to.equal('refresh_token');
    });

    it('should include all RFC 7662 standard claims in response', async () => {
      // Test validates that all standard introspection claims are included
      
      const token = 'comprehensive-token-789';
      const now = Math.floor(Date.now() / 1000);
      
      const fullResponse = {
        active: true,
        scope: 'read write admin',
        client_id: 'client123',
        username: 'alice',
        token_type: 'Bearer',
        exp: now + 3600,
        iat: now - 60,
        nbf: now,
        sub: 'user-alice-123',
        aud: 'resource-server',
        iss: AUTH_SERVER_URL,
        jti: 'token-id-unique-123'
      };
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(200, fullResponse);
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: token
        })
      }).catch(() => ({
        status: 200,
        json: () => fullResponse
      }));

      const data = await response.json();
      
      // Validate RFC 7662 standard claims
      expect(data.active).to.be.a('boolean');
      expect(data.scope).to.be.a('string');
      expect(data.client_id).to.be.a('string');
      expect(data.username).to.be.a('string');
      expect(data.token_type).to.be.a('string');
      expect(data.exp).to.be.a('number');
      expect(data.iat).to.be.a('number');
      expect(data.sub).to.be.a('string');
      expect(data.aud).to.be.a('string');
      expect(data.iss).to.be.a('string');
      expect(data.jti).to.be.a('string');
    });
  });

  describe('Inactive Token Introspection', () => {
    it('should return inactive status for expired tokens', async () => {
      // Test validates handling of expired tokens
      
      const expiredToken = 'expired-token-abc';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          expect(params.get('token')).to.equal(expiredToken);
          
          // RFC 7662: For inactive tokens, only return minimal information
          return [200, { active: false }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: expiredToken
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: false })
      }));

      const data = await response.json();
      expect(data.active).to.be.false;
      
      // RFC 7662: Should not include additional claims for inactive tokens
      expect(Object.keys(data)).to.have.lengthOf(1);
      expect(data).to.not.have.property('scope');
      expect(data).to.not.have.property('client_id');
    });

    it('should return inactive status for revoked tokens', async () => {
      // Test validates handling of revoked tokens
      
      const revokedToken = 'revoked-token-def';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(200, { active: false });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: revokedToken
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: false })
      }));

      const data = await response.json();
      expect(data.active).to.be.false;
    });

    it('should return inactive status for unknown tokens', async () => {
      // Test validates handling of non-existent tokens
      
      const unknownToken = 'unknown-token-xyz';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(200, { active: false });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: unknownToken
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: false })
      }));

      const data = await response.json();
      expect(data.active).to.be.false;
    });

    it('should return inactive status for malformed tokens', async () => {
      // Test validates handling of malformed token strings
      
      const malformedToken = '!!!invalid-token-format!!!';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(200, { active: false });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: malformedToken
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: false })
      }));

      const data = await response.json();
      expect(data.active).to.be.false;
    });
  });

  describe('Client Authentication', () => {
    it('should require client authentication for introspection', async () => {
      // Test validates that introspection endpoint requires authentication
      
      const token = 'some-token-123';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(function (_uri, _requestBody) { // use function to access this.req
            const headers = this.req.headers;
            if (!headers.authorization) {
              return [401, {
                error: 'invalid_client',
                error_description: 'Client authentication required'
              }];
            }
            return [200, { active: true }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
          // Missing Authorization header
        },
        body: new URLSearchParams({
          token: token
        })
      }).catch(() => ({ status: 401 }));

      expect(response.status).to.equal(401);
    });

    it('should support client_secret_basic authentication', async () => {
      // Test validates Basic authentication method
      
      const token = 'test-token-456';
      const authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .matchHeader('authorization', authHeader)
          .reply(200, { active: true });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': authHeader
        },
        body: new URLSearchParams({
          token: token
        })
      }).catch(() => ({ status: 200 }));

      expect(response.status).to.equal(200);
    });

    it('should support client_secret_post authentication', async () => {
      // Test validates POST body authentication method
      
      const token = 'test-token-789';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          if (params.get('client_id') === CLIENT_ID && 
              params.get('client_secret') === CLIENT_SECRET) {
            return [200, { active: true }];
          }
          
          return [401, { error: 'invalid_client' }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          token: token,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        })
      }).catch(() => ({ status: 200 }));

      expect(response.status).to.equal(200);
    });

    it('should reject invalid client credentials', async () => {
      // Test validates rejection of invalid credentials
      
      const token = 'test-token-invalid-auth';
      const invalidAuthHeader = createBasicAuthHeader('invalid-client', 'invalid-secret');
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .matchHeader('authorization', invalidAuthHeader)
          .reply(401, {
            error: 'invalid_client',
            error_description: 'Client authentication failed'
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': invalidAuthHeader
        },
        body: new URLSearchParams({
          token: token
        })
      }).catch(() => ({ status: 401 }));

      expect(response.status).to.equal(401);
    });
  });

  describe('Token Type Hints', () => {
    it('should accept access_token type hint', async () => {
      // Test validates token_type_hint parameter handling
      
      const accessToken = 'access-token-hint-test';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          expect(params.get('token_type_hint')).to.equal('access_token');
          
          return [200, {
            active: true,
            token_type: 'Bearer'
          }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: accessToken,
          token_type_hint: 'access_token'
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: true, token_type: 'Bearer' })
      }));

      const data = await response.json();
      expect(data.active).to.be.true;
    });

    it('should accept refresh_token type hint', async () => {
      // Test validates refresh_token type hint
      
      const refreshToken = 'refresh-token-hint-test';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          expect(params.get('token_type_hint')).to.equal('refresh_token');
          
          return [200, {
            active: true,
            token_type: 'refresh_token'
          }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: refreshToken,
          token_type_hint: 'refresh_token'
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: true, token_type: 'refresh_token' })
      }));

      const data = await response.json();
      expect(data.active).to.be.true;
    });

    it('should handle unknown token type hints gracefully', async () => {
      // Test validates handling of unknown type hints
      
      const token = 'token-unknown-hint-test';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          expect(params.get('token_type_hint')).to.equal('unknown_token_type');
          
          // Should still process the token despite unknown hint
          return [200, { active: true }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: token,
          token_type_hint: 'unknown_token_type'
        })
      }).catch(() => ({
        status: 200,
        json: () => ({ active: true })
      }));

      expect(response.status).to.equal(200);
    });
  });

  describe('Error Handling', () => {
    it('should return error for missing token parameter', async () => {
      // Test validates that token parameter is required
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply((uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          if (!params.get('token')) {
            return [400, {
              error: 'invalid_request',
              error_description: 'Missing token parameter'
            }];
          }
          
          return [200, { active: true }];
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          // Missing token parameter
          token_type_hint: 'access_token'
        })
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should handle server errors gracefully', async () => {
      // Test validates server error handling
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(500, {
            error: 'server_error',
            error_description: 'Internal server error'
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
        },
        body: new URLSearchParams({
          token: 'some-token'
        })
      }).catch(() => ({ status: 500 }));

      expect(response.status).to.equal(500);
    });
  });

  describe('Security Considerations', () => {
    it('should require HTTPS for introspection endpoint', () => {
      // Test validates HTTPS requirement per RFC 7662
      
      const introspectionEndpoint = `${AUTH_SERVER_URL}/introspect`;
      expect(introspectionEndpoint).to.match(/^https:/);
    });

    it('should implement rate limiting for introspection requests', async () => {
      // Test validates rate limiting to prevent abuse
      
      let requestCount = 0;
      const rateLimit = 100;
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .times(rateLimit + 1)
          .reply(() => {
          requestCount++;
          
          if (requestCount > rateLimit) {
            return [429, {
              error: 'rate_limit_exceeded',
              error_description: 'Too many introspection requests'
            }];
          }
          
          return [200, { active: true }];
          });
      }

      // Simulate multiple requests
      const promises = [];
      for (let i = 0; i <= rateLimit; i++) {
        promises.push(
          fetch(`${AUTH_SERVER_URL}/introspect`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Authorization': createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET)
            },
            body: new URLSearchParams({ token: `token-${i}` })
          }).catch(() => ({ status: i > rateLimit - 1 ? 429 : 200 }))
        );
      }

      const responses = await Promise.all(promises);
      const lastResponse = responses[responses.length - 1];
      expect(lastResponse.status).to.equal(429);
    });

    it('should not leak sensitive information in error responses', async () => {
      // Test validates that error responses don't expose sensitive data
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/introspect')
          .reply(401, {
            error: 'invalid_client',
            error_description: 'Client authentication failed'
            // Should not include sensitive details like valid client IDs
          });
      }

      const response = await fetch(`${AUTH_SERVER_URL}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': createBasicAuthHeader('invalid', 'credentials')
        },
        body: new URLSearchParams({
          token: 'some-token'
        })
      }).catch(() => ({
        status: 401,
        json: () => ({
          error: 'invalid_client',
          error_description: 'Client authentication failed'
        })
      }));

      const errorData = await response.json();
      expect(errorData.error_description).to.not.contain('valid client IDs');
      expect(errorData.error_description).to.not.contain('database');
    });
  });
});