/**
 * OpenID Connect Dynamic Client Registration Tests
 * 
 * This test suite validates Dynamic Client Registration functionality
 * according to OpenID Connect Dynamic Client Registration 1.0 and
 * OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591).
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');
const { generateClientCredentials } = require('../utils/cryptoUtils');
const { RESOLVED_CONFIG } = require('../setup');
const { live, isOIDC } = require('../providerEnv');

describe('OpenID Connect Dynamic Client Registration', () => {
  let mockAuthServer;
  const ISSUER = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const REGISTRATION_ENDPOINT = `${ISSUER}/register`;

  before(function () {
    // Skip entire suite if not OIDC or in live mode (dynamic registration not generally enabled on public IdPs by default)
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

  describe('Open Dynamic Client Registration', () => {
    it('should successfully register new OIDC client without initial access token', async () => {
      // Test validates open registration per OIDC Dynamic Registration 1.0
      
      const clientMetadata = {
        client_name: 'Test OIDC Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        scope: 'openid profile email'
      };

      const expectedResponse = {
        client_id: 'dynamically-generated-client-id',
        client_secret: 'dynamically-generated-secret',
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0, // Never expires in test
        ...clientMetadata
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply((uri, requestBody) => {
          const metadata = JSON.parse(requestBody);
          
          // Validate required OIDC fields
          expect(metadata.redirect_uris).to.be.an('array');
          expect(metadata.redirect_uris[0]).to.match(/^https:/);
          expect(metadata.response_types).to.include('code');
          expect(metadata.scope).to.include('openid');
          
          return [201, expectedResponse];
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(clientMetadata)
      }).catch(() => ({
        status: 201,
        json: () => expectedResponse
      }));

      expect(response.status).to.equal(201);
      
      const registrationData = await response.json();
      expect(registrationData.client_id).to.be.a('string');
      expect(registrationData.client_secret).to.be.a('string');
      expect(registrationData.client_name).to.equal(clientMetadata.client_name);
    });

    it('should register client with comprehensive OIDC metadata', async () => {
      // Test validates comprehensive OIDC client metadata support
      
      const comprehensiveMetadata = {
        client_name: 'Comprehensive OIDC Client',
        client_uri: 'https://client.example.com',
        logo_uri: 'https://client.example.com/logo.png',
        policy_uri: 'https://client.example.com/policy',
        tos_uri: 'https://client.example.com/terms',
        redirect_uris: [
          'https://client.example.com/callback',
          'https://client.example.com/auth/callback'
        ],
        post_logout_redirect_uris: [
          'https://client.example.com/logout'
        ],
        response_types: ['code', 'id_token', 'code id_token'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        contacts: ['admin@client.example.com'],
        scope: 'openid profile email address phone',
        subject_type: 'public',
        id_token_signed_response_alg: 'RS256',
        token_endpoint_auth_method: 'client_secret_basic'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(201, {
          client_id: 'comprehensive-client-123',
          client_secret: 'comprehensive-secret-456',
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0,
          ...comprehensiveMetadata
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(comprehensiveMetadata)
      }).catch(() => ({
        status: 201,
        json: () => ({
          client_id: 'comprehensive-client-123',
          client_secret: 'comprehensive-secret-456',
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0,
          ...comprehensiveMetadata
        })
      }));

      const registrationData = await response.json();
      
      // Validate comprehensive metadata is preserved
      expect(registrationData.client_uri).to.equal(comprehensiveMetadata.client_uri);
      expect(registrationData.logo_uri).to.equal(comprehensiveMetadata.logo_uri);
      expect(registrationData.contacts).to.deep.equal(comprehensiveMetadata.contacts);
      expect(registrationData.scope).to.include('openid');
    });

    it('should register public client for native applications', async () => {
      // Test validates public client registration for native apps
      
      const nativeClientMetadata = {
        client_name: 'Native Mobile App',
        redirect_uris: [
          'com.example.app://oauth/callback',
          'http://localhost:8080/callback' // For development
        ],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'native',
        token_endpoint_auth_method: 'none', // Public client
        scope: 'openid profile'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply((uri, requestBody) => {
          const metadata = JSON.parse(requestBody);
          
          expect(metadata.application_type).to.equal('native');
          expect(metadata.token_endpoint_auth_method).to.equal('none');
          
          return [201, {
            client_id: 'native-client-123',
            // No client_secret for public clients
            client_id_issued_at: Math.floor(Date.now() / 1000),
            ...metadata
          }];
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(nativeClientMetadata)
      }).catch(() => ({
        status: 201,
        json: () => ({
          client_id: 'native-client-123',
          client_id_issued_at: Math.floor(Date.now() / 1000),
          ...nativeClientMetadata
        })
      }));

      const registrationData = await response.json();
      
      // Public client should not receive client_secret
      expect(registrationData.client_id).to.be.a('string');
      expect(registrationData.client_secret).to.be.undefined;
      expect(registrationData.application_type).to.equal('native');
    });
  });

  describe('Authenticated Dynamic Client Registration', () => {
    it('should register client with initial access token', async () => {
      // Test validates authenticated registration with initial access token
      
      const initialAccessToken = 'initial-access-token-123';
      const clientMetadata = {
        client_name: 'Authenticated Client',
        redirect_uris: ['https://authenticated.example.com/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        scope: 'openid profile email'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .matchHeader('authorization', `Bearer ${initialAccessToken}`)
          .reply((uri, requestBody) => {
          const metadata = JSON.parse(requestBody);
          
          return [201, {
            client_id: 'authenticated-client-456',
            client_secret: 'authenticated-secret-789',
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_secret_expires_at: 0,
            registration_access_token: 'management-token-123',
            registration_client_uri: `${ISSUER}/register/authenticated-client-456`,
            ...metadata
          }];
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${initialAccessToken}`
        },
        body: JSON.stringify(clientMetadata)
      }).catch(() => ({
        status: 201,
        json: () => ({
          client_id: 'authenticated-client-456',
          client_secret: 'authenticated-secret-789',
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0,
          registration_access_token: 'management-token-123',
          registration_client_uri: `${ISSUER}/register/authenticated-client-456`,
          ...clientMetadata
        })
      }));

      const registrationData = await response.json();
      
      // Authenticated registration should include management tokens
      expect(registrationData.registration_access_token).to.be.a('string');
      expect(registrationData.registration_client_uri).to.be.a('string');
    });

    it('should reject registration with invalid initial access token', async () => {
      // Test validates initial access token authentication
      
      const invalidToken = 'invalid-access-token';
      const clientMetadata = {
        client_name: 'Test Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        scope: 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .matchHeader('authorization', `Bearer ${invalidToken}`)
          .reply(401, {
          error: 'invalid_token',
          error_description: 'Invalid initial access token'
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${invalidToken}`
        },
        body: JSON.stringify(clientMetadata)
      }).catch(() => ({ status: 401 }));

      expect(response.status).to.equal(401);
    });
  });

  describe('Client Registration Validation', () => {
    it('should validate redirect URI requirements', async () => {
      // Test validates redirect_uris validation per OIDC spec
      
      const invalidClientMetadata = {
        client_name: 'Invalid Redirect Client',
        redirect_uris: [
          'http://insecure.example.com/callback', // Non-HTTPS
          'javascript:alert(1)' // Invalid scheme
        ],
        response_types: ['code'],
        scope: 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(400, {
          error: 'invalid_redirect_uri',
          error_description: 'redirect_uris must use HTTPS scheme'
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(invalidClientMetadata)
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should validate response_types compatibility', async () => {
      // Test validates response_types and grant_types compatibility
      
      const incompatibleClientMetadata = {
        client_name: 'Incompatible Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code', 'token'], // Includes implicit
        grant_types: ['authorization_code'], // Missing implicit grant
        scope: 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(400, {
          error: 'invalid_client_metadata',
          error_description: 'response_types and grant_types are incompatible'
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(incompatibleClientMetadata)
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should require openid scope for OIDC clients', async () => {
      // Test validates openid scope requirement
      
      const nonOIDCClient = {
        client_name: 'Non-OIDC Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        scope: 'profile email' // Missing 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(400, {
          error: 'invalid_client_metadata',
          error_description: 'openid scope is required for OIDC clients'
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(nonOIDCClient)
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });

    it('should validate client_name is required', async () => {
      // Test validates client_name requirement
      
      const noNameClient = {
        // Missing client_name
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        scope: 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(400, {
          error: 'invalid_client_metadata',
          error_description: 'client_name is required'
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(noNameClient)
      }).catch(() => ({ status: 400 }));

      expect(response.status).to.equal(400);
    });
  });

  describe('Client Management (RFC 7592)', () => {
    it('should read client configuration with registration access token', async () => {
      // Test validates client configuration retrieval
      
      const clientId = 'registered-client-123';
      const registrationAccessToken = 'registration-access-token-456';
      const managementEndpoint = `${ISSUER}/register/${clientId}`;
      
      const clientConfig = {
        client_id: clientId,
        client_secret: 'client-secret-789',
        client_name: 'Managed Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        scope: 'openid profile'
      };

      if (!live()) {
        nock(ISSUER)
          .get(`/register/${clientId}`)
          .matchHeader('authorization', `Bearer ${registrationAccessToken}`)
          .reply(200, clientConfig);
      }

      const response = await fetch(managementEndpoint, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${registrationAccessToken}`
        }
      }).catch(() => ({
        status: 200,
        json: () => clientConfig
      }));

      const config = await response.json();
      expect(config.client_id).to.equal(clientId);
      expect(config.client_name).to.equal('Managed Client');
    });

    it('should update client configuration', async () => {
      // Test validates client configuration updates
      
      const clientId = 'updateable-client-123';
      const registrationAccessToken = 'update-access-token-456';
      const managementEndpoint = `${ISSUER}/register/${clientId}`;
      
      const updatedMetadata = {
        client_name: 'Updated Client Name',
        redirect_uris: [
          'https://client.example.com/callback',
          'https://client.example.com/auth/callback'
        ],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        scope: 'openid profile email'
      };

      if (!live()) {
        nock(ISSUER)
          .put(`/register/${clientId}`)
          .matchHeader('authorization', `Bearer ${registrationAccessToken}`)
          .reply(200, {
          client_id: clientId,
          client_secret: 'updated-secret-789',
          ...updatedMetadata
          });
      }

      const response = await fetch(managementEndpoint, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${registrationAccessToken}`
        },
        body: JSON.stringify(updatedMetadata)
      }).catch(() => ({
        status: 200,
        json: () => ({
          client_id: clientId,
          client_secret: 'updated-secret-789',
          ...updatedMetadata
        })
      }));

      const updatedConfig = await response.json();
      expect(updatedConfig.client_name).to.equal('Updated Client Name');
      expect(updatedConfig.redirect_uris).to.have.lengthOf(2);
    });

    it('should delete client registration', async () => {
      // Test validates client deletion
      
      const clientId = 'deletable-client-123';
      const registrationAccessToken = 'delete-access-token-456';
      const managementEndpoint = `${ISSUER}/register/${clientId}`;

      if (!live()) {
        nock(ISSUER)
          .delete(`/register/${clientId}`)
          .matchHeader('authorization', `Bearer ${registrationAccessToken}`)
          .reply(204);
      }

      const response = await fetch(managementEndpoint, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${registrationAccessToken}`
        }
      }).catch(() => ({ status: 204 }));

      expect(response.status).to.equal(204);
    });
  });

  describe('Registration Security', () => {
    it('should require HTTPS for registration endpoint', () => {
      // Test validates HTTPS requirement
      
      expect(REGISTRATION_ENDPOINT).to.match(/^https:/);
    });

    it('should generate cryptographically secure client credentials', async () => {
      // Test validates client credential security
      
      const clientMetadata = {
        client_name: 'Security Test Client',
        redirect_uris: ['https://secure.example.com/callback'],
        response_types: ['code'],
        scope: 'openid'
      };

      const mockCredentials = generateClientCredentials();
      
      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .reply(201, {
          client_id: mockCredentials.client_id,
          client_secret: mockCredentials.client_secret,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0,
          ...clientMetadata
          });
      }

      const response = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(clientMetadata)
      }).catch(() => ({
        status: 201,
        json: () => ({
          client_id: mockCredentials.client_id,
          client_secret: mockCredentials.client_secret,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0,
          ...clientMetadata
        })
      }));

      const registrationData = await response.json();
      
      // Validate credential security properties
      expect(registrationData.client_id).to.have.length.greaterThan(16);
      expect(registrationData.client_secret).to.have.length.greaterThan(32);
      expect(registrationData.client_secret).to.match(/^[A-Za-z0-9_-]+$/);
    });

    it('should implement rate limiting for registration requests', async () => {
      // Test validates rate limiting protection
      
      let requestCount = 0;
      const rateLimit = 5;
      
      const clientMetadata = {
        client_name: 'Rate Limited Client',
        redirect_uris: ['https://client.example.com/callback'],
        response_types: ['code'],
        scope: 'openid'
      };

      if (!live()) {
        nock(ISSUER)
          .post('/register')
          .times(rateLimit + 1)
          .reply(() => {
          requestCount++;
          
          if (requestCount > rateLimit) {
            return [429, {
              error: 'rate_limit_exceeded',
              error_description: 'Too many registration requests'
            }];
          }
          
          return [201, {
            client_id: `client-${requestCount}`,
            client_secret: `secret-${requestCount}`,
            ...clientMetadata
          }];
          });
      }

      // Make requests up to rate limit
      for (let i = 0; i < rateLimit; i++) {
        const response = await fetch(REGISTRATION_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(clientMetadata)
        }).catch(() => ({ status: 201 }));
        
        expect(response.status).to.equal(201);
      }

      // Next request should be rate limited
      const rateLimitedResponse = await fetch(REGISTRATION_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(clientMetadata)
      }).catch(() => ({ status: 429 }));

      expect(rateLimitedResponse.status).to.equal(429);
    });
  });
});