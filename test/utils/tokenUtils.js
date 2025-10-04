/**
 * Token Utilities for OAuth 2.1 and OIDC Testing
 * 
 * This module provides utility functions for creating, validating,
 * and manipulating tokens in compliance with OAuth 2.1 and OIDC specifications.
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const jwksClient = require('jwks-rsa');

/**
 * Generate a secure random access token
 * @param {number} length - Token length in bytes
 * @returns {string} Hex-encoded access token
 */
const generateAccessToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate a secure refresh token with entropy
 * @param {number} length - Token length in bytes  
 * @returns {string} Base64URL-encoded refresh token
 */
const generateRefreshToken = (length = 64) => {
  return crypto.randomBytes(length).toString('base64url');
};

/**
 * Generate authorization code for OAuth flows
 * @param {number} length - Code length in bytes
 * @returns {string} Base64URL-encoded authorization code
 */
const generateAuthorizationCode = (length = 32) => {
  return crypto.randomBytes(length).toString('base64url');
};

/**
 * Create JWT ID token with proper OIDC claims
 * @param {Object} payload - Token payload
 * @param {Object} options - Signing options
 * @param {string} privateKey - Private key for signing
 * @returns {string} Signed JWT ID token
 */
const createIdToken = (payload, options = {}, privateKey) => {
  const now = Math.floor(Date.now() / 1000);
  
  const defaultPayload = {
    iat: now,
    exp: now + 3600, // 1 hour expiration
    auth_time: now,
    ...payload
  };

  const defaultOptions = {
    algorithm: 'RS256',
    keyid: 'test-key-1',
    header: {
      typ: 'JWT'
    },
    ...options
  };

  return jwt.sign(defaultPayload, privateKey, defaultOptions);
};

/**
 * Create JWT access token (RFC 9068 compliant)
 * @param {Object} payload - Token payload
 * @param {Object} options - Signing options
 * @param {string} privateKey - Private key for signing
 * @returns {string} Signed JWT access token
 */
const createJwtAccessToken = (payload, options = {}, privateKey) => {
  const now = Math.floor(Date.now() / 1000);
  
  const defaultPayload = {
    iat: now,
    exp: now + 3600,
    token_use: 'access_token',
    ...payload
  };

  const defaultOptions = {
    algorithm: 'RS256',
    keyid: 'test-key-1',
    ...options
  };

  return jwt.sign(defaultPayload, privateKey, defaultOptions);
};

/**
 * Validate JWT token structure and basic claims
 * @param {string} token - JWT token to validate
 * @param {string} publicKey - Public key for verification
 * @param {Object} options - Verification options
 * @returns {Object} Decoded token payload
 */
const validateJwt = (token, publicKey, options = {}) => {
  const defaultOptions = {
    algorithms: ['RS256'],
    clockTolerance: 30, // 30 seconds clock tolerance
    ...options
  };

  try {
    return jwt.verify(token, publicKey, defaultOptions);
  } catch (error) {
    throw new Error(`JWT validation failed: ${error.message}`);
  }
};

/**
 * Decode JWT without verification (for inspection)
 * @param {string} token - JWT token to decode
 * @returns {Object} Decoded token with header, payload, signature
 */
const decodeJwt = (token) => {
  return jwt.decode(token, { complete: true });
};

/**
 * Validate ID token according to OIDC Core 1.0 spec
 * @param {string} idToken - ID token to validate
 * @param {Object} validationParams - Validation parameters
 * @param {string} publicKey - Public key for signature verification
 * @returns {Object} Validated token payload
 */
const validateIdToken = (idToken, validationParams, publicKey) => {
  const { clientId, issuer, nonce, maxAge } = validationParams;
  
  // First verify the signature
  const payload = validateJwt(idToken, publicKey, {
    audience: clientId,
    issuer: issuer
  });

  // Validate OIDC-specific claims
  if (nonce && payload.nonce !== nonce) {
    throw new Error('Nonce mismatch in ID token');
  }

  // Validate auth_time if max_age was specified
  if (maxAge && payload.auth_time) {
    const authTime = payload.auth_time;
    const now = Math.floor(Date.now() / 1000);
    if (now - authTime > maxAge) {
      throw new Error('ID token auth_time exceeds max_age');
    }
  }

  // Ensure required OIDC claims are present
  const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
  for (const claim of requiredClaims) {
    if (!payload[claim]) {
      throw new Error(`Missing required claim: ${claim}`);
    }
  }

  return payload;
};

/**
 * Create introspection response according to RFC 7662
 * @param {string} token - Token to introspect
 * @param {Object} tokenInfo - Token metadata
 * @returns {Object} Introspection response
 */
const createIntrospectionResponse = (token, tokenInfo) => {
  const now = Math.floor(Date.now() / 1000);
  
  // Check if token is expired
  const isActive = tokenInfo.exp ? tokenInfo.exp > now : true;
  
  if (!isActive) {
    return { active: false };
  }

  return {
    active: true,
    client_id: tokenInfo.client_id,
    username: tokenInfo.username,
    scope: tokenInfo.scope,
    exp: tokenInfo.exp,
    iat: tokenInfo.iat,
    token_type: tokenInfo.token_type || 'Bearer',
    sub: tokenInfo.sub
  };
};

/**
 * Generate JTI (JWT ID) claim
 * @returns {string} Unique JWT identifier
 */
const generateJti = () => {
  return crypto.randomUUID();
};

/**
 * Create token response for authorization code exchange
 * @param {Object} params - Token response parameters
 * @returns {Object} OAuth 2.1 compliant token response
 */
const createTokenResponse = (params) => {
  const {
    accessToken,
    tokenType = 'Bearer',
    expiresIn = 3600,
    refreshToken,
    idToken,
    scope
  } = params;

  const response = {
    access_token: accessToken,
    token_type: tokenType,
    expires_in: expiresIn
  };

  if (refreshToken) {
    response.refresh_token = refreshToken;
  }

  if (idToken) {
    response.id_token = idToken;
  }

  if (scope) {
    response.scope = scope;
  }

  return response;
};

/**
 * Validate token response structure
 * @param {Object} tokenResponse - Token response to validate
 * @returns {boolean} Validation result
 */
const validateTokenResponse = (tokenResponse) => {
  const requiredFields = ['access_token', 'token_type'];
  
  for (const field of requiredFields) {
    if (!tokenResponse[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }

  // Validate token_type is Bearer
  if (tokenResponse.token_type !== 'Bearer') {
    throw new Error('Invalid token_type, must be Bearer');
  }

  // Validate expires_in if present
  if (tokenResponse.expires_in && !Number.isInteger(tokenResponse.expires_in)) {
    throw new Error('expires_in must be an integer');
  }

  return true;
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateAuthorizationCode,
  createIdToken,
  createJwtAccessToken,
  validateJwt,
  decodeJwt,
  validateIdToken,
  createIntrospectionResponse,
  generateJti,
  createTokenResponse,
  validateTokenResponse
};