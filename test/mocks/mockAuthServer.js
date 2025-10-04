/**
 * Mock Authorization Server for OAuth 2.1 and OIDC Testing
 * 
 * This module provides a comprehensive mock implementation of an OAuth 2.1
 * and OpenID Connect authorization server for testing purposes.
 */

const nock = require('nock');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { 
  generateAccessToken, 
  generateRefreshToken, 
  generateAuthorizationCode,
  createIdToken,
  createTokenResponse,
  createIntrospectionResponse
} = require('../utils/tokenUtils');
const { 
  generateCodeChallenge, 
  verifyCodeChallenge,
  createBasicAuthHeader 
} = require('../utils/cryptoUtils');

class MockAuthServer {
  constructor(baseUrl = 'https://auth.example.com') {
    this.baseUrl = baseUrl;
    this.scope = nock(baseUrl);
    this.clients = new Map();
    this.authorizationCodes = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
    this.introspectionTokens = new Map();
    
    // Default test keys
    this.keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    this.issuer = baseUrl;
    this.setupDefaultClient();
  }

  /**
   * Setup default test client
   */
  setupDefaultClient() {
    this.clients.set('test-client-id', {
      client_id: 'test-client-id',
      client_secret: 'test-client-secret',
      redirect_uris: ['https://client.example.com/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid profile email'
    });
  }

  /**
   * Mock OpenID Connect Discovery endpoint
   * Returns well-known configuration according to OIDC Discovery 1.0
   */
  mockDiscovery() {
    this.scope
      .get('/.well-known/openid-configuration')
      .reply(200, {
        issuer: this.issuer,
        authorization_endpoint: `${this.baseUrl}/authorize`,
        token_endpoint: `${this.baseUrl}/token`,
        userinfo_endpoint: `${this.baseUrl}/userinfo`,
        jwks_uri: `${this.baseUrl}/.well-known/jwks.json`,
        introspection_endpoint: `${this.baseUrl}/introspect`,
        registration_endpoint: `${this.baseUrl}/register`,
        end_session_endpoint: `${this.baseUrl}/logout`,
        check_session_iframe: `${this.baseUrl}/check_session`,
        revocation_endpoint: `${this.baseUrl}/revoke`,
        
        // Supported response types
        response_types_supported: ['code', 'id_token', 'id_token token', 'code id_token', 'code token', 'code id_token token'],
        
        // Supported subject types
        subject_types_supported: ['public'],
        
        // Supported signing algorithms
        id_token_signing_alg_values_supported: ['RS256'],
        
        // Supported scopes
        scopes_supported: ['openid', 'profile', 'email', 'address', 'phone'],
        
        // Supported token endpoint auth methods
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        
        // Supported claims
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified'],
        
        // PKCE support
        code_challenge_methods_supported: ['S256'],
        
        // Grant types supported
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials']
      })
      .persist();

    return this;
  }

  /**
   * Mock JWKS endpoint
   * Returns JSON Web Key Set for token verification
   */
  mockJwks() {
    // Convert PEM to JWK (simplified for testing)
    const jwks = {
      keys: [{
        kty: 'RSA',
        use: 'sig',
        kid: 'test-key-1',
        alg: 'RS256',
        n: 'test-modulus-value',
        e: 'AQAB'
      }]
    };

    this.scope
      .get('/.well-known/jwks.json')
      .reply(200, jwks)
      .persist();

    return this;
  }

  /**
   * Mock authorization endpoint
   * Handles OAuth 2.1 authorization requests with mandatory PKCE
   */
  mockAuthorize(options = {}) {
    const {
      requirePkce = true,
      requireState = true,
      allowedResponseTypes = ['code'],
      allowedScopes = ['openid', 'profile', 'email']
    } = options;

    this.scope
      .get('/authorize')
      .query(true)
      .reply((uri, requestBody, callback) => {
        const url = new URL(uri, this.baseUrl);
        const params = Object.fromEntries(url.searchParams);

        // Validate required parameters
        const requiredParams = ['response_type', 'client_id', 'redirect_uri'];
        for (const param of requiredParams) {
          if (!params[param]) {
            return callback(null, [400, { 
              error: 'invalid_request', 
              error_description: `Missing required parameter: ${param}` 
            }]);
          }
        }

        // Validate client
        const client = this.clients.get(params.client_id);
        if (!client) {
          return callback(null, [400, { 
            error: 'invalid_client', 
            error_description: 'Unknown client' 
          }]);
        }

        // Validate redirect URI (exact match required in OAuth 2.1)
        if (!client.redirect_uris.includes(params.redirect_uri)) {
          return callback(null, [400, { 
            error: 'invalid_request', 
            error_description: 'Invalid redirect_uri' 
          }]);
        }

        // Validate response type
        if (!allowedResponseTypes.includes(params.response_type)) {
          return callback(null, [400, { 
            error: 'unsupported_response_type', 
            error_description: `Unsupported response_type: ${params.response_type}` 
          }]);
        }

        // OAuth 2.1 requires PKCE for authorization code flow
        if (params.response_type === 'code' && requirePkce) {
          if (!params.code_challenge) {
            return callback(null, [400, { 
              error: 'invalid_request', 
              error_description: 'PKCE code_challenge required' 
            }]);
          }
          
          if (!params.code_challenge_method) {
            params.code_challenge_method = 'plain'; // Default per RFC 7636
          }
          
          // OAuth 2.1 strongly recommends S256
          if (params.code_challenge_method !== 'S256') {
            return callback(null, [400, { 
              error: 'invalid_request', 
              error_description: 'code_challenge_method must be S256' 
            }]);
          }
        }

        // Validate state parameter for CSRF protection
        if (requireState && !params.state) {
          return callback(null, [400, { 
            error: 'invalid_request', 
            error_description: 'state parameter required' 
          }]);
        }

        // Generate authorization code
        const authCode = generateAuthorizationCode();
        
        // Store authorization code with metadata
        this.authorizationCodes.set(authCode, {
          client_id: params.client_id,
          redirect_uri: params.redirect_uri,
          scope: params.scope || 'openid',
          code_challenge: params.code_challenge,
          code_challenge_method: params.code_challenge_method,
          nonce: params.nonce,
          state: params.state,
          expires_at: Date.now() + 600000 // 10 minutes
        });

        // Build callback URL
        const callbackUrl = new URL(params.redirect_uri);
        callbackUrl.searchParams.set('code', authCode);
        if (params.state) {
          callbackUrl.searchParams.set('state', params.state);
        }

        // Return redirect response
        callback(null, [302, '', { 'Location': callbackUrl.toString() }]);
      })
      .persist();

    return this;
  }

  /**
   * Mock token endpoint
   * Handles token exchange with PKCE verification
   */
  mockToken() {
    this.scope
      .post('/token')
      .reply((uri, requestBody, callback) => {
        let params;
        
        // Parse request body (form-encoded)
        if (typeof requestBody === 'string') {
          params = Object.fromEntries(new URLSearchParams(requestBody));
        } else {
          params = requestBody;
        }

        const grantType = params.grant_type;

        if (grantType === 'authorization_code') {
          return this._handleAuthorizationCodeGrant(params, callback);
        } else if (grantType === 'refresh_token') {
          return this._handleRefreshTokenGrant(params, callback);
        } else if (grantType === 'client_credentials') {
          return this._handleClientCredentialsGrant(params, callback);
        } else {
          return callback(null, [400, { 
            error: 'unsupported_grant_type', 
            error_description: `Unsupported grant_type: ${grantType}` 
          }]);
        }
      })
      .persist();

    return this;
  }

  /**
   * Handle authorization code grant
   */
  _handleAuthorizationCodeGrant(params, callback) {
    // Validate required parameters
    if (!params.code || !params.redirect_uri || !params.client_id) {
      return callback(null, [400, { 
        error: 'invalid_request', 
        error_description: 'Missing required parameters' 
      }]);
    }

    // Retrieve authorization code
    const codeData = this.authorizationCodes.get(params.code);
    if (!codeData) {
      return callback(null, [400, { 
        error: 'invalid_grant', 
        error_description: 'Invalid authorization code' 
      }]);
    }

    // Check expiration
    if (Date.now() > codeData.expires_at) {
      this.authorizationCodes.delete(params.code);
      return callback(null, [400, { 
        error: 'invalid_grant', 
        error_description: 'Authorization code expired' 
      }]);
    }

    // Validate client and redirect URI
    if (codeData.client_id !== params.client_id || 
        codeData.redirect_uri !== params.redirect_uri) {
      return callback(null, [400, { 
        error: 'invalid_grant', 
        error_description: 'Invalid client or redirect_uri' 
      }]);
    }

    // Verify PKCE if code_challenge was present
    if (codeData.code_challenge) {
      if (!params.code_verifier) {
        return callback(null, [400, { 
          error: 'invalid_request', 
          error_description: 'code_verifier required' 
        }]);
      }

      if (!verifyCodeChallenge(params.code_verifier, codeData.code_challenge, codeData.code_challenge_method)) {
        return callback(null, [400, { 
          error: 'invalid_grant', 
          error_description: 'PKCE verification failed' 
        }]);
      }
    }

    // Generate tokens
    const accessToken = generateAccessToken();
    const refreshToken = generateRefreshToken();
    
    // Create ID token if OpenID Connect scope
    let idToken = null;
    if (codeData.scope.includes('openid')) {
      const idTokenPayload = {
        iss: this.issuer,
        sub: 'user123',
        aud: params.client_id,
        nonce: codeData.nonce,
        auth_time: Math.floor(Date.now() / 1000) - 10
      };
      
      idToken = createIdToken(idTokenPayload, {}, this.keyPair.privateKey);
    }

    // Store tokens
    this.accessTokens.set(accessToken, {
      client_id: params.client_id,
      scope: codeData.scope,
      expires_at: Date.now() + 3600000 // 1 hour
    });

    this.refreshTokens.set(refreshToken, {
      client_id: params.client_id,
      scope: codeData.scope,
      access_token: accessToken
    });

    // Invalidate authorization code (single use)
    this.authorizationCodes.delete(params.code);

    // Create token response
    const tokenResponse = createTokenResponse({
      accessToken,
      refreshToken,
      idToken,
      scope: codeData.scope,
      expiresIn: 3600
    });

    callback(null, [200, tokenResponse]);
  }

  /**
   * Handle refresh token grant
   */
  _handleRefreshTokenGrant(params, callback) {
    if (!params.refresh_token) {
      return callback(null, [400, { 
        error: 'invalid_request', 
        error_description: 'Missing refresh_token' 
      }]);
    }

    const refreshData = this.refreshTokens.get(params.refresh_token);
    if (!refreshData) {
      return callback(null, [400, { 
        error: 'invalid_grant', 
        error_description: 'Invalid refresh_token' 
      }]);
    }

    // Generate new tokens (rotate refresh token per OAuth 2.1)
    const newAccessToken = generateAccessToken();
    const newRefreshToken = generateRefreshToken();

    // Invalidate old refresh token
    this.refreshTokens.delete(params.refresh_token);
    
    // Store new tokens
    this.accessTokens.set(newAccessToken, {
      client_id: refreshData.client_id,
      scope: refreshData.scope,
      expires_at: Date.now() + 3600000
    });

    this.refreshTokens.set(newRefreshToken, {
      client_id: refreshData.client_id,
      scope: refreshData.scope,
      access_token: newAccessToken
    });

    const tokenResponse = createTokenResponse({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      scope: refreshData.scope,
      expiresIn: 3600
    });

    callback(null, [200, tokenResponse]);
  }

  /**
   * Handle client credentials grant
   */
  _handleClientCredentialsGrant(params, callback) {
    // Authenticate client (simplified)
    const client = this.clients.get(params.client_id);
    if (!client || client.client_secret !== params.client_secret) {
      return callback(null, [401, { 
        error: 'invalid_client', 
        error_description: 'Client authentication failed' 
      }]);
    }

    const accessToken = generateAccessToken();
    
    this.accessTokens.set(accessToken, {
      client_id: params.client_id,
      scope: params.scope || '',
      expires_at: Date.now() + 3600000,
      token_type: 'Bearer'
    });

    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: params.scope || ''
    };

    callback(null, [200, tokenResponse]);
  }

  /**
   * Mock token introspection endpoint (RFC 7662)
   */
  mockIntrospection() {
    this.scope
      .post('/introspect')
      .reply((uri, requestBody, callback) => {
        let params;
        if (typeof requestBody === 'string') {
          params = Object.fromEntries(new URLSearchParams(requestBody));
        } else {
          params = requestBody;
        }

        if (!params.token) {
          return callback(null, [400, { 
            error: 'invalid_request', 
            error_description: 'Missing token parameter' 
          }]);
        }

        // Check if token exists in our stores
        const tokenData = this.accessTokens.get(params.token) || 
                         this.refreshTokens.get(params.token);

        if (!tokenData) {
          return callback(null, [200, { active: false }]);
        }

        // Check if token is expired
        if (tokenData.expires_at && Date.now() > tokenData.expires_at) {
          return callback(null, [200, { active: false }]);
        }

        const introspectionResponse = createIntrospectionResponse(params.token, {
          client_id: tokenData.client_id,
          scope: tokenData.scope,
          exp: Math.floor(tokenData.expires_at / 1000),
          iat: Math.floor((tokenData.expires_at - 3600000) / 1000),
          token_type: 'Bearer',
          sub: 'user123',
          username: 'testuser'
        });

        callback(null, [200, introspectionResponse]);
      })
      .persist();

    return this;
  }

  /**
   * Mock UserInfo endpoint
   */
  mockUserInfo() {
    this.scope
      .get('/userinfo')
      .reply((uri, requestBody, callback) => {
        // Extract bearer token from Authorization header
        const authHeader = this.scope.interceptors[0].headers?.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return callback(null, [401, { 
            error: 'invalid_token', 
            error_description: 'Missing or invalid access token' 
          }]);
        }

        const token = authHeader.substring(7);
        const tokenData = this.accessTokens.get(token);

        if (!tokenData || !tokenData.scope.includes('openid')) {
          return callback(null, [401, { 
            error: 'insufficient_scope', 
            error_description: 'Token lacks required scope' 
          }]);
        }

        // Return user claims based on scope
        const userInfo = {
          sub: 'user123'
        };

        if (tokenData.scope.includes('profile')) {
          userInfo.name = 'Test User';
          userInfo.given_name = 'Test';
          userInfo.family_name = 'User';
        }

        if (tokenData.scope.includes('email')) {
          userInfo.email = 'test@example.com';
          userInfo.email_verified = true;
        }

        callback(null, [200, userInfo]);
      })
      .persist();

    return this;
  }

  /**
   * Mock dynamic client registration endpoint
   */
  mockRegistration() {
    this.scope
      .post('/register')
      .reply((uri, requestBody, callback) => {
        const metadata = JSON.parse(requestBody);

        // Generate client credentials
        const clientId = `client_${crypto.randomBytes(8).toString('hex')}`;
        const clientSecret = crypto.randomBytes(32).toString('base64url');

        // Store client
        this.clients.set(clientId, {
          client_id: clientId,
          client_secret: clientSecret,
          ...metadata
        });

        const response = {
          client_id: clientId,
          client_secret: clientSecret,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0, // Never expires in test
          ...metadata
        };

        callback(null, [201, response]);
      })
      .persist();

    return this;
  }

  /**
   * Setup complete mock server
   */
  setupAll() {
    return this.mockDiscovery()
               .mockJwks()
               .mockAuthorize()
               .mockToken()
               .mockIntrospection()
               .mockUserInfo()
               .mockRegistration();
  }

  /**
   * Clean up all mocks
   */
  cleanup() {
    nock.cleanAll();
  }
}

module.exports = MockAuthServer;