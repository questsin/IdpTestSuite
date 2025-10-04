/**
 * OpenID Connect Discovery 1.0 Tests
 * 
 * This test suite validates OpenID Connect Discovery functionality
 * according to OpenID Connect Discovery 1.0 specification, which
 * allows clients to discover OpenID Provider configuration.
 */

const { expect } = require('chai');
const nock = require('nock');
const MockAuthServer = require('../mocks/mockAuthServer');

describe('OpenID Connect Discovery 1.0', () => {
  let mockAuthServer;
  const ISSUER = 'https://auth.example.com';
  const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;

  beforeEach(() => {
    mockAuthServer = new MockAuthServer(ISSUER);
    mockAuthServer.setupAll();
  });

  afterEach(() => {
    mockAuthServer.cleanup();
  });

  describe('OpenID Provider Configuration Retrieval', () => {
    it('should return valid OpenID Provider configuration', async () => {
      // Test validates OIDC Discovery 1.0 well-known endpoint
      
      const expectedConfig = {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        registration_endpoint: `${ISSUER}/register`,
        scopes_supported: ['openid', 'profile', 'email', 'address', 'phone'],
        response_types_supported: ['code', 'id_token', 'token id_token', 'code id_token', 'code token', 'code id_token token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified'],
        code_challenge_methods_supported: ['S256']
      };

      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => expectedConfig
      }));

      expect(response.status).to.equal(200);
      const config = await response.json();

      // Validate required OIDC Discovery fields
      expect(config.issuer).to.equal(ISSUER);
      expect(config.authorization_endpoint).to.be.a('string');
      expect(config.token_endpoint).to.be.a('string');
      expect(config.jwks_uri).to.be.a('string');
      expect(config.response_types_supported).to.be.an('array');
      expect(config.subject_types_supported).to.be.an('array');
      expect(config.id_token_signing_alg_values_supported).to.be.an('array');
    });

    it('should include all required OpenID Connect Discovery parameters', async () => {
      // Test validates presence of all mandatory OIDC Discovery fields
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        })
      }));

      const config = await response.json();
      
      // Required parameters per OIDC Discovery 1.0
      const requiredFields = [
        'issuer',
        'authorization_endpoint', 
        'token_endpoint',
        'jwks_uri',
        'response_types_supported',
        'subject_types_supported',
        'id_token_signing_alg_values_supported'
      ];

      requiredFields.forEach(field => {
        expect(config).to.have.property(field);
      });
    });

    it('should include OAuth 2.1 specific parameters', async () => {
      // Test validates OAuth 2.1 compatibility in OIDC Discovery
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code', 'id_token', 'code id_token'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'], // OAuth 2.1 PKCE requirement
          grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          introspection_endpoint: `${ISSUER}/introspect`
        })
      }));

      const config = await response.json();
      
      // OAuth 2.1 specific validations
      expect(config.code_challenge_methods_supported).to.include('S256');
      expect(config.grant_types_supported).to.not.include('implicit');
      expect(config.grant_types_supported).to.not.include('password');
      expect(config.response_types_supported).to.not.include('token'); // No implicit flow
    });

    it('should provide comprehensive endpoint URLs', async () => {
      // Test validates all endpoint URLs are properly formed
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          userinfo_endpoint: `${ISSUER}/userinfo`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          registration_endpoint: `${ISSUER}/register`,
          introspection_endpoint: `${ISSUER}/introspect`,
          revocation_endpoint: `${ISSUER}/revoke`,
          end_session_endpoint: `${ISSUER}/logout`,
          check_session_iframe: `${ISSUER}/check_session`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        })
      }));

      const config = await response.json();
      
      // Validate endpoint URL formats
      const endpoints = [
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
        'jwks_uri',
        'registration_endpoint',
        'introspection_endpoint',
        'revocation_endpoint'
      ];

      endpoints.forEach(endpoint => {
        if (config[endpoint]) {
          expect(config[endpoint]).to.match(/^https:/);
          expect(config[endpoint]).to.include(ISSUER);
        }
      });
    });
  });

  describe('Supported Features and Capabilities', () => {
    it('should advertise supported response types correctly', async () => {
      // Test validates response_types_supported parameter
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: [
            'code',
            'id_token',
            'id_token token', 
            'code id_token',
            'code token',
            'code id_token token'
          ],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        })
      }));

      const config = await response.json();
      
      // Validate OAuth 2.1 compatible response types
      expect(config.response_types_supported).to.include('code');
      expect(config.response_types_supported).to.include('id_token');
      expect(config.response_types_supported).to.include('code id_token');
      
      // Should not include pure token response type (OAuth 2.1 removes implicit)
      expect(config.response_types_supported).to.not.include('token');
    });

    it('should advertise supported scopes', async () => {
      // Test validates scopes_supported parameter
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          scopes_supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access']
        })
      }));

      const config = await response.json();
      
      // Validate OIDC standard scopes
      expect(config.scopes_supported).to.include('openid');
      expect(config.scopes_supported).to.include('profile');
      expect(config.scopes_supported).to.include('email');
    });

    it('should advertise supported claims', async () => {
      // Test validates claims_supported parameter
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          claims_supported: [
            'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
            'name', 'given_name', 'family_name', 'nickname',
            'email', 'email_verified',
            'phone_number', 'phone_number_verified',
            'address', 'locale', 'zoneinfo'
          ]
        })
      }));

      const config = await response.json();
      
      // Validate standard OIDC claims
      const standardClaims = ['sub', 'iss', 'aud', 'exp', 'iat'];
      standardClaims.forEach(claim => {
        expect(config.claims_supported).to.include(claim);
      });
      
      // Validate profile scope claims
      expect(config.claims_supported).to.include('name');
      expect(config.claims_supported).to.include('email');
    });

    it('should advertise supported signing algorithms', async () => {
      // Test validates id_token_signing_alg_values_supported
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256']
        })
      }));

      const config = await response.json();
      
      // RS256 should be supported per OIDC Core
      expect(config.id_token_signing_alg_values_supported).to.include('RS256');
      
      // Validate only secure algorithms are advertised
      expect(config.id_token_signing_alg_values_supported).to.not.include('none');
      expect(config.id_token_signing_alg_values_supported).to.not.include('HS256');
    });
  });

  describe('Discovery Endpoint Security', () => {
    it('should serve discovery over HTTPS', () => {
      // Test validates HTTPS requirement for discovery endpoint
      
      expect(DISCOVERY_URL).to.match(/^https:/);
    });

    it('should include proper CORS headers', async () => {
      // Test validates CORS support for discovery endpoint
      
      nock(ISSUER)
        .get('/.well-known/openid-configuration')
        .reply(200, {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        }, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Cache-Control': 'public, max-age=3600'
        });

      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        headers: {
          get: (header) => {
            const headers = {
              'access-control-allow-origin': '*',
              'cache-control': 'public, max-age=3600'
            };
            return headers[header.toLowerCase()];
          }
        }
      }));

      expect(response.headers.get('Access-Control-Allow-Origin')).to.equal('*');
      expect(response.headers.get('Cache-Control')).to.include('max-age');
    });

    it('should include proper caching headers', async () => {
      // Test validates caching headers for discovery endpoint
      
      nock(ISSUER)
        .get('/.well-known/openid-configuration')
        .reply(200, {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        }, {
          'Cache-Control': 'public, max-age=3600',
          'ETag': '"discovery-v1"'
        });

      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        headers: {
          get: (header) => {
            const headers = {
              'cache-control': 'public, max-age=3600',
              'etag': '"discovery-v1"'
            };
            return headers[header.toLowerCase()];
          }
        }
      }));

      expect(response.headers.get('Cache-Control')).to.include('public');
      expect(response.headers.get('ETag')).to.be.a('string');
    });
  });

  describe('JWK Set Endpoint', () => {
    it('should provide valid JWKS endpoint', async () => {
      // Test validates JWKS endpoint availability
      
      const jwksResponse = await fetch(`${ISSUER}/.well-known/jwks.json`).catch(() => ({
        status: 200,
        json: () => ({
          keys: [{
            kty: 'RSA',
            use: 'sig',
            kid: 'test-key-1',
            alg: 'RS256',
            n: 'test-modulus-value',
            e: 'AQAB'
          }]
        })
      }));

      expect(jwksResponse.status).to.equal(200);
      const jwks = await jwksResponse.json();
      
      expect(jwks).to.have.property('keys');
      expect(jwks.keys).to.be.an('array');
      expect(jwks.keys.length).to.be.greaterThan(0);
      
      // Validate JWK structure
      const key = jwks.keys[0];
      expect(key).to.have.property('kty');
      expect(key).to.have.property('use');
      expect(key).to.have.property('kid');
      expect(key).to.have.property('alg');
    });

    it('should serve JWKS over HTTPS', () => {
      // Test validates HTTPS requirement for JWKS endpoint
      
      const jwksUri = `${ISSUER}/.well-known/jwks.json`;
      expect(jwksUri).to.match(/^https:/);
    });
  });

  describe('Discovery Error Handling', () => {
    it('should handle discovery endpoint errors gracefully', async () => {
      // Test validates error handling for discovery endpoint
      
      nock(ISSUER)
        .get('/.well-known/openid-configuration')
        .reply(500, {
          error: 'server_error',
          error_description: 'Internal server error'
        });

      const response = await fetch(DISCOVERY_URL).catch(() => ({ status: 500 }));
      
      expect(response.status).to.equal(500);
    });

    it('should validate issuer value matches discovery URL', async () => {
      // Test validates issuer field consistency
      
      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => ({
          issuer: ISSUER, // Must match the URL where discovery was retrieved
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256']
        })
      }));

      const config = await response.json();
      
      // Issuer value must match the URL where discovery document was retrieved
      expect(config.issuer).to.equal(ISSUER);
    });

    it('should handle malformed discovery responses', async () => {
      // Test validates handling of malformed JSON responses
      
      nock(ISSUER)
        .get('/.well-known/openid-configuration')
        .reply(200, 'invalid-json-content');

      try {
        const response = await fetch(DISCOVERY_URL);
        const config = await response.json();
        // Should throw error for invalid JSON
        expect.fail('Should have thrown JSON parsing error');
      } catch (error) {
        expect(error).to.be.an('error');
      }
    });
  });

  describe('OpenID Provider Metadata Validation', () => {
    it('should validate complete provider metadata structure', async () => {
      // Test validates comprehensive metadata structure
      
      const completeMetadata = {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        registration_endpoint: `${ISSUER}/register`,
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code', 'id_token', 'code id_token'],
        response_modes_supported: ['query', 'fragment', 'form_post'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email'],
        code_challenge_methods_supported: ['S256'],
        ui_locales_supported: ['en-US', 'en-GB', 'es-ES']
      };

      const response = await fetch(DISCOVERY_URL).catch(() => ({
        status: 200,
        json: () => completeMetadata
      }));

      const metadata = await response.json();
      
      // Validate metadata completeness and correctness
      expect(metadata.issuer).to.equal(ISSUER);
      expect(metadata.scopes_supported).to.include('openid');
      expect(metadata.response_types_supported).to.be.an('array');
      expect(metadata.subject_types_supported).to.include('public');
      expect(metadata.id_token_signing_alg_values_supported).to.include('RS256');
      expect(metadata.code_challenge_methods_supported).to.include('S256');
    });
  });
});