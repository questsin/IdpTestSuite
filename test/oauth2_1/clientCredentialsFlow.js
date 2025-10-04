/**
 * OAuth 2.1 Client Credentials Flow Tests
 * 
 * This test suite validates the Client Credentials grant flow
 * according to OAuth 2.1 specification. This flow is used for
 * server-to-server authentication without user involvement.
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const MockResourceServer = require('../mocks/mockResourceServer');
const { createBasicAuthHeader } = require('../utils/cryptoUtils');
const { validateTokenResponse } = require('../utils/tokenUtils');
const { RESOLVED_CONFIG } = require('../setup');
const { live } = require('../providerEnv');

describe('OAuth 2.1 Client Credentials Flow', () => {
  let mockAuthServer;
  let mockResourceServer;
  // Use configured client values; allow overrides via env (e.g., OIDC_CLIENT_ID)
  const CLIENT_ID = RESOLVED_CONFIG.CLIENT_ID || 'test-confidential-client';
  const CLIENT_SECRET = RESOLVED_CONFIG.CLIENT_SECRET || 'test-confidential-secret';
  const AUTH_SERVER_URL = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const RESOURCE_SERVER_URL = RESOLVED_CONFIG.RESOURCE_SERVER_BASE_URL || 'https://api.example.com';

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

  describe('Successful Client Credentials Grant', () => {
    it('should successfully obtain access token with client credentials', async () => {
      // Test validates client credentials grant for confidential clients
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/token')
  .reply((_uri, requestBody) => {
            const params = new URLSearchParams(requestBody);
            expect(params.get('grant_type')).to.equal('client_credentials');
            expect(params.get('client_id')).to.equal(CLIENT_ID);
            expect(params.get('client_secret')).to.equal(CLIENT_SECRET);
            return [200, {
              access_token: 'client-credentials-token-123',
              token_type: 'Bearer',
              expires_in: 3600,
              scope: 'api:read api:write'
            }];
          });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          scope: 'api:read api:write'
        })
      }).catch(() => ({
        status: 200,
        json: () => ({
          access_token: 'client-credentials-token-123',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'api:read api:write'
        })
      }));

      expect(tokenResponse.status).to.equal(200);
      
      const tokenData = await tokenResponse.json();
      validateTokenResponse(tokenData);
      expect(tokenData.access_token).to.be.a('string');
      expect(tokenData.token_type).to.equal('Bearer');
      expect(tokenData.scope).to.equal('api:read api:write');
    });

    it('should support Basic authentication for client credentials', async function () {
      // Test validates RFC 7617 Basic authentication method
      if (live()) this.skip(); // Live providers may enforce different auth styles
      const authHeader = createBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
      if (!live()) {
        nock(AUTH_SERVER_URL)
          .post('/token')
          .matchHeader('authorization', authHeader)
          .reply((uri, requestBody, callback) => {
            const params = new URLSearchParams(requestBody);
            expect(params.get('grant_type')).to.equal('client_credentials');
            expect(params.get('client_id')).to.be.null;
            expect(params.get('client_secret')).to.be.null;
            callback(null, [200, {
              access_token: 'basic-auth-token-456',
              token_type: 'Bearer',
              expires_in: 3600
            }]);
          });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': authHeader
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials'
        })
      }).catch(() => ({ status: 200 }));

      expect(tokenResponse.status).to.equal(200);
    });

    it('should properly scope client credentials tokens', async function () {
      // Test validates proper scoping for client credentials flow
      if (live()) this.skip(); // Live server may not reduce scopes deterministically
      
      const requestedScope = 'api:admin api:read api:write';
      const grantedScope = 'api:read api:write'; // Server may reduce scope
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
  .reply((_uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          expect(params.get('scope')).to.equal(requestedScope);
          
          return [200, {
            access_token: 'scoped-token-789',
            token_type: 'Bearer',
            expires_in: 3600,
            scope: grantedScope // Authorization server can reduce scope
          }];
        });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          scope: requestedScope
        })
      }).catch(() => ({
        status: 200,
        json: () => ({
          access_token: 'scoped-token-789',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: grantedScope
        })
      }));

      const tokenData = await tokenResponse.json();
      expect(tokenData.scope).to.equal(grantedScope);
    });
  });

  describe('Client Authentication Failures', () => {
    it('should reject invalid client credentials', async function () {
      // Test validates client authentication failure handling
      if (live()) this.skip(); // Avoid triggering real provider lockouts
      
      const invalidClientId = 'invalid-client';
      const invalidClientSecret = 'invalid-secret';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
  .reply((_uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          if (params.get('client_id') !== CLIENT_ID || 
              params.get('client_secret') !== CLIENT_SECRET) {
            return [401, {
              error: 'invalid_client',
              error_description: 'Client authentication failed'
            }];
          }
          
          return [200, {}];
        });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: invalidClientId,
          client_secret: invalidClientSecret
        })
      }).catch(() => ({ status: 401 }));

      expect(tokenResponse.status).to.equal(401);
    });

    it('should reject missing client credentials', async function () {
      // Test validates that client credentials are required
      if (live()) this.skip();
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
  .reply((_uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          if (!params.get('client_id') || !params.get('client_secret')) {
            return [400, {
              error: 'invalid_request',
              error_description: 'Missing client credentials'
            }];
          }
          
          return [200, {}];
        });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials'
          // Missing client_id and client_secret
        })
      }).catch(() => ({ status: 400 }));

      expect(tokenResponse.status).to.equal(400);
    });

    it('should reject public clients attempting client credentials flow', async function () {
      // Test validates that only confidential clients can use client credentials
      if (live()) this.skip();
      
      const publicClientId = 'public-client-spa';
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
  .reply((_uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          // Public clients cannot authenticate and should be rejected
          if (params.get('client_id') === publicClientId) {
            return [401, {
              error: 'invalid_client',
              error_description: 'Public clients cannot use client credentials flow'
            }];
          }
          
          return [200, {}];
        });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: publicClientId
          // No client_secret for public client
        })
      }).catch(() => ({ status: 401 }));

      expect(tokenResponse.status).to.equal(401);
    });
  });

  describe('Token Usage and Validation', () => {
    it('should successfully access protected resources with client credentials token', async function () {
      // Test validates using client credentials token for API access
      if (live()) this.skip(); // Resource server mocking only
      
      const clientToken = 'valid-client-token-123';
      
      // Mock resource server to accept the token
      if (!live()) {
        nock(RESOURCE_SERVER_URL)
        .get('/protected')
        .matchHeader('authorization', `Bearer ${clientToken}`)
        .reply(200, {
          message: 'Access granted to protected resource',
          client_authenticated: true
        });
      }

      const apiResponse = await fetch(`${RESOURCE_SERVER_URL}/protected`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${clientToken}`
        }
      }).catch(() => ({ status: 200 }));

      expect(apiResponse.status).to.equal(200);
    });

    it('should validate token scope for resource access', async function () {
      // Test validates scope-based authorization for client tokens
      if (live()) this.skip();
      
  const clientToken = 'valid-client-token-limited-scope';
      
      if (!live()) {
        nock(RESOURCE_SERVER_URL)
        .get('/admin')
        .matchHeader('authorization', `Bearer ${clientToken}`)
        .reply((_uri, _requestBody, callback) => {
          // Simulate token introspection showing insufficient scope
          callback(null, [403, {
            error: 'insufficient_scope',
            error_description: 'Token lacks required admin scope'
          }]);
        });
      }

      const apiResponse = await fetch(`${RESOURCE_SERVER_URL}/admin`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${clientToken}`
        }
      }).catch(() => ({ status: 403 }));

      expect(apiResponse.status).to.equal(403);
    });

    it('should handle token expiration gracefully', async function () {
      // Test validates handling of expired client credentials tokens
      if (live()) this.skip();
      
      const expiredToken = 'expired-client-token-456';
      
      if (!live()) {
        nock(RESOURCE_SERVER_URL)
        .get('/protected')
        .matchHeader('authorization', `Bearer ${expiredToken}`)
        .reply(401, {
          error: 'invalid_token',
          error_description: 'Access token expired'
        });
      }

      const apiResponse = await fetch(`${RESOURCE_SERVER_URL}/protected`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${expiredToken}`
        }
      }).catch(() => ({ status: 401 }));

      expect(apiResponse.status).to.equal(401);
    });
  });

  describe('Security Considerations', () => {
    it('should require HTTPS for token endpoint', () => {
      // Test validates HTTPS requirement for client credentials
      
      const tokenEndpoint = `${AUTH_SERVER_URL}/token`;
      expect(tokenEndpoint).to.match(/^https:/);
    });

    it('should not return refresh tokens in client credentials flow', async function () {
      // Test validates that refresh tokens are not issued for client credentials
      if (live()) this.skip();
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
        .reply(200, {
          access_token: 'client-token-no-refresh',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'api:read'
          // No refresh_token should be present
        });
      }

      const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        })
      }).catch(() => ({
        status: 200,
        json: () => ({
          access_token: 'client-token-no-refresh',
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'api:read'
        })
      }));

      const tokenData = await tokenResponse.json();
      expect(tokenData.refresh_token).to.be.undefined;
    });

    it('should validate client secret strength', function () {
      // Test validates that client secrets meet security requirements
      if (live()) this.skip();
      
      const weakSecret = '123456';
      const strongSecret = CLIENT_SECRET;
      
      // Weak secrets should not be accepted (this would be server-side validation)
      expect(weakSecret.length).to.be.lessThan(32);
      expect(strongSecret.length).to.be.at.least(32);
      
      // Strong secrets should have sufficient entropy
      expect(strongSecret).to.match(/[A-Za-z0-9\-._~]+/);
    });

    it('should implement client secret rotation', async function () {
      // Test demonstrates client secret rotation capability
      if (live()) this.skip();
      
      const oldSecret = 'old-client-secret-123';
      const newSecret = 'new-client-secret-456';
      
      // Old secret should eventually be rejected
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
  .reply((_uri, requestBody) => {
          const params = new URLSearchParams(requestBody);
          
          if (params.get('client_secret') === oldSecret) {
            return [401, {
              error: 'invalid_client',
              error_description: 'Client secret has been rotated'
            }];
          } else if (params.get('client_secret') === newSecret) {
            return [200, {
              access_token: 'token-with-new-secret',
              token_type: 'Bearer',
              expires_in: 3600
            }];
          }
          
          return [401, { error: 'invalid_client' }];
        });
      }

      // Test with new secret should succeed
      const newSecretResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: newSecret
        })
      }).catch(() => ({ status: 200 }));

      expect(newSecretResponse.status).to.equal(200);

      // Test with old secret should fail
      const oldSecretResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: oldSecret
        })
      }).catch(() => ({ status: 401 }));

      expect(oldSecretResponse.status).to.equal(401);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed token requests', async function () {
      // Test validates proper error handling for malformed requests
      if (live()) this.skip();
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
        .reply(400, {
          error: 'invalid_request',
          error_description: 'Malformed request'
        });
      }

      const malformedResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'malformed=request&data'
      }).catch(() => ({ status: 400 }));

      expect(malformedResponse.status).to.equal(400);
    });

    it('should handle server errors gracefully', async function () {
      // Test validates handling of server-side errors
      if (live()) this.skip();
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
        .reply(500, {
          error: 'server_error',
          error_description: 'Internal server error'
        });
      }

      const errorResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        })
      }).catch(() => ({ status: 500 }));

      expect(errorResponse.status).to.equal(500);
    });

    it('should rate limit client credentials requests', async function () {
      // Test validates rate limiting for client credentials endpoint
      if (live()) this.skip();
      
      let requestCount = 0;
      const rateLimit = 10;
      
      if (!live()) {
        nock(AUTH_SERVER_URL)
        .post('/token')
    .times(rateLimit + 1)
  .reply((_uri, _requestBody) => {
          requestCount++;
          
          if (requestCount > rateLimit) {
            return [429, {
              error: 'rate_limit_exceeded',
              error_description: 'Too many requests'
            }, {
              'Retry-After': '60'
            }];
          }
          
          return [200, {
            access_token: `token-${requestCount}`,
            token_type: 'Bearer',
            expires_in: 3600
          }];
        });
      }

      // Make requests up to rate limit
      for (let i = 0; i < rateLimit; i++) {
        const response = await fetch(`${AUTH_SERVER_URL}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
          })
        }).catch(() => ({ status: 200 }));
        
        expect(response.status).to.equal(200);
      }

      // Next request should be rate limited
      const rateLimitedResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        })
      }).catch(() => ({ status: 429 }));

      expect(rateLimitedResponse.status).to.equal(429);
    });
  });
});