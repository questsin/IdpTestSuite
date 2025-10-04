/**
 * Mock Resource Server for OAuth 2.1 and OIDC Testing
 * 
 * This module provides a mock implementation of a resource server
 * that validates OAuth 2.1 tokens and serves protected resources.
 */

const nock = require('nock');
// crypto not required after refactor; removed

class MockResourceServer {
  constructor(baseUrl = 'https://api.example.com') {
    this.baseUrl = baseUrl;
    this.scope = nock(baseUrl);
    this.resources = new Map();
    this.setupDefaultResources();
  }

  /**
   * Setup default test resources
   */
  setupDefaultResources() {
    this.resources.set('/protected', {
      data: 'This is protected data',
      requiredScope: 'read'
    });
    
    this.resources.set('/admin', {
      data: 'Admin-only data',
      requiredScope: 'admin'
    });
    
    this.resources.set('/profile', {
      data: {
        user_id: 'user123',
        name: 'Test User',
        email: 'test@example.com'
      },
      requiredScope: 'profile'
    });
  }

  /**
   * Mock protected resource endpoint with token validation
   * @param {string} path - Resource path
   * @param {Object} options - Mock options
   */
  mockProtectedResource(path = '/protected', options = {}) {
    const {
      requiredScope = null,
      validateToken = true,
      authServerUrl = 'https://auth.example.com',
      methods = ['GET']
    } = options;

    methods.forEach(method => {
      const mockMethod = method.toLowerCase();
      
      const serverInstance = this;
      this.scope[mockMethod](path)
        .reply(function (uri, requestBody, callback) { // function to access this.req
          const authHeader = this.req.headers['authorization'];
          
          if (!authHeader) {
            return callback(null, [401, { 
              error: 'invalid_request',
              error_description: 'Missing Authorization header' 
            }]);
          }

          if (!authHeader.startsWith('Bearer ')) {
            return callback(null, [401, { 
              error: 'invalid_token',
              error_description: 'Invalid token type, Bearer expected' 
            }]);
          }

          const token = authHeader.substring(7);
          
          if (!token) {
            return callback(null, [401, { 
              error: 'invalid_token',
              error_description: 'Missing access token' 
            }]);
          }

          if (validateToken) {
            // In real implementation, this would call token introspection
            // or validate JWT signature. For testing, we simulate validation.
            serverInstance._validateTokenViaIntrospection(token, authServerUrl, (err, tokenInfo) => {
              if (err || !tokenInfo.active) {
                return callback(null, [401, { 
                  error: 'invalid_token',
                  error_description: 'Token validation failed' 
                }]);
              }

              // Check required scope
              if (requiredScope && !serverInstance._hasRequiredScope(tokenInfo.scope, requiredScope)) {
                return callback(null, [403, { 
                  error: 'insufficient_scope',
                  error_description: `Required scope: ${requiredScope}` 
                }]);
              }

              // Return protected resource
              const resource = serverInstance.resources.get(path);
              callback(null, [200, resource ? resource.data : { message: 'Access granted' }]);
            });
          } else {
            const resource = serverInstance.resources.get(path);
            callback(null, [200, resource ? resource.data : { message: 'Access granted' }]);
          }
        })
        .persist();
    });

    return this;
  }

  /**
   * Simulate token introspection call
   * @param {string} token - Token to validate
   * @param {string} authServerUrl - Authorization server URL
   * @param {Function} callback - Callback function
   */
  _validateTokenViaIntrospection(token, authServerUrl, callback) {
    // This simulates calling the auth server's introspection endpoint
    // In real implementation, this would be an actual HTTP call
    
    // For testing, we'll simulate different token scenarios
    if (token === 'invalid-token') {
      return callback(null, { active: false });
    }
    
    if (token === 'expired-token') {
      return callback(null, { active: false });
    }
    
    if (token.startsWith('valid-')) {
      const scope = token.includes('admin') ? 'admin' : 'read profile';
      return callback(null, {
        active: true,
        client_id: 'test-client-id',
        username: 'testuser',
        scope: scope,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_type: 'Bearer',
        sub: 'user123'
      });
    }

    // Default to invalid
    callback(null, { active: false });
  }

  /**
   * Check if token has required scope
   * @param {string} tokenScope - Scope from token
   * @param {string} requiredScope - Required scope
   * @returns {boolean} True if scope is sufficient
   */
  _hasRequiredScope(tokenScope, requiredScope) {
    if (!tokenScope) return false;
    
    const scopes = tokenScope.split(' ');
    return scopes.includes(requiredScope);
  }

  /**
   * Mock API endpoint that requires specific HTTP method
   * @param {string} method - HTTP method
   * @param {string} path - Resource path
   * @param {Object} options - Mock options
   */
  mockHttpMethodEndpoint(method, path, options = {}) {
    const mockMethod = method.toLowerCase();
    const { requiredScope, responseData } = options;

    this.scope[mockMethod](path)
      .reply(function (uri, requestBody, callback) {
        const authHeader = this.req.headers['authorization'];
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return callback(null, [401, { 
            error: 'invalid_token',
            error_description: 'Invalid or missing authorization' 
          }]);
        }

        const token = authHeader.substring(7);
        
        // Simple token validation for testing
        if (token.startsWith('valid-')) {
          const tokenScope = token.includes('admin') ? 'admin write' : 'read';
          
          if (requiredScope && !this._hasRequiredScope(tokenScope, requiredScope)) {
            return callback(null, [403, { 
              error: 'insufficient_scope',
              error_description: `Required scope: ${requiredScope}` 
            }]);
          }

          callback(null, [200, responseData || { 
            method: method.toUpperCase(),
            path: path,
            message: 'Success'
          }]);
        } else {
          callback(null, [401, { 
            error: 'invalid_token',
            error_description: 'Token validation failed' 
          }]);
        }
      })
      .persist();

    return this;
  }

  /**
   * Mock CORS preflight endpoint
   * @param {string} path - Resource path
   */
  mockCorsPreflightEndpoint(path) {
    this.scope
      .options(path)
      .reply(200, '', {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Access-Control-Max-Age': '86400'
      })
      .persist();

    return this;
  }

  /**
   * Mock rate-limited endpoint
   * @param {string} path - Resource path
   * @param {Object} options - Rate limiting options
   */
  mockRateLimitedEndpoint(path, options = {}) {
    const { 
      limit = 10, 
      window = 60,
      resetTime = Math.floor(Date.now() / 1000) + window 
    } = options;
    
    let requestCount = 0;

    this.scope
      .get(path)
      .reply(function (uri, requestBody, callback) {
        requestCount++;
        
        const headers = {
          'X-RateLimit-Limit': limit.toString(),
          'X-RateLimit-Remaining': Math.max(0, limit - requestCount).toString(),
          'X-RateLimit-Reset': resetTime.toString()
        };

        if (requestCount > limit) {
          callback(null, [429, { 
            error: 'rate_limit_exceeded',
            error_description: 'Too many requests' 
          }, headers]);
        } else {
          callback(null, [200, { 
            message: 'Rate limit OK',
            request_count: requestCount 
          }, headers]);
        }
      })
      .persist();

    return this;
  }

  /**
   * Mock error scenarios for testing
   * @param {string} path - Resource path
   * @param {number} statusCode - HTTP status code
   * @param {Object} errorResponse - Error response body
   */
  mockErrorScenario(path, statusCode = 500, errorResponse = {}) {
    const defaultError = {
      error: 'server_error',
      error_description: 'Internal server error'
    };

    this.scope
      .get(path)
      .reply(statusCode, { ...defaultError, ...errorResponse })
      .persist();

    return this;
  }

  /**
   * Mock endpoint with custom response delay
   * @param {string} path - Resource path
   * @param {number} delay - Delay in milliseconds
   * @param {Object} responseData - Response data
   */
  mockDelayedEndpoint(path, delay = 1000, responseData = {}) {
    this.scope
      .get(path)
      .delay(delay)
      .reply(200, { 
        message: 'Delayed response',
        delay: delay,
        ...responseData 
      })
      .persist();

    return this;
  }

  /**
   * Setup common protected endpoints
   */
  setupCommonEndpoints() {
    return this
      .mockProtectedResource('/protected', { requiredScope: 'read' })
      .mockProtectedResource('/admin', { requiredScope: 'admin' })
      .mockProtectedResource('/profile', { requiredScope: 'profile' })
      .mockHttpMethodEndpoint('POST', '/data', { requiredScope: 'write' })
      .mockHttpMethodEndpoint('PUT', '/data', { requiredScope: 'write' })
      .mockHttpMethodEndpoint('DELETE', '/data', { requiredScope: 'admin' })
      .mockCorsPreflightEndpoint('/protected')
      .mockRateLimitedEndpoint('/throttled');
  }

  /**
   * Mock JWT-based resource endpoint
   * @param {string} path - Resource path
   * @param {Object} options - JWT validation options
   */
  mockJwtProtectedResource(path, options = {}) {
    const { publicKey, issuer, audience } = options;

    this.scope
      .get(path)
      .reply((uri, requestBody, callback) => {
        const authHeader = this.scope.interceptors[0].headers?.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return callback(null, [401, { 
            error: 'invalid_token',
            error_description: 'Missing Bearer token' 
          }]);
        }

        const token = authHeader.substring(7);
        
        try {
          // In real implementation, would validate JWT signature
          // For testing, we simulate JWT validation
          const jwt = require('jsonwebtoken');
          const decoded = jwt.decode(token, { complete: true });
          
          if (!decoded || !decoded.payload) {
            throw new Error('Invalid JWT structure');
          }

          // Simulate successful validation
          callback(null, [200, {
            message: 'JWT validation successful',
            subject: decoded.payload.sub,
            scopes: decoded.payload.scope
          }]);
          
        } catch (error) {
          callback(null, [401, { 
            error: 'invalid_token',
            error_description: 'JWT validation failed' 
          }]);
        }
      })
      .persist();

    return this;
  }

  /**
   * Clean up all mocks
   */
  cleanup() {
    nock.cleanAll();
  }
}

module.exports = MockResourceServer;