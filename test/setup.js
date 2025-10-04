
const chai = require('chai');
const nock = require('nock');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
// Mocha root hook plugin pattern used below; no need to import BDD globals here.

// Global test configuration
global.expect = chai.expect;
global.should = chai.should();

// Test environment configuration
process.env.NODE_ENV = 'test';

// Default test configuration constants
const TEST_CONFIG = {
  AUTH_SERVER_BASE_URL: 'https://auth.example.com',
  RESOURCE_SERVER_BASE_URL: 'https://api.example.com',
  CLIENT_ID: 'test-client-id',
  CLIENT_SECRET: 'test-client-secret',
  REDIRECT_URI: 'https://client.example.com/callback',
  SCOPE: 'openid profile email',
  ISSUER: 'https://auth.example.com',
  AUDIENCE: 'test-api',
  
  // PKCE Configuration
  PKCE: {
    CODE_VERIFIER_LENGTH: 64,
    CODE_CHALLENGE_METHOD: 'S256'
  },
  
  // JWT Configuration
  JWT: {
    ALGORITHM: 'RS256',
    EXPIRES_IN: '1h',
    REFRESH_EXPIRES_IN: '24h'
  },
  
  // Timeouts
  TIMEOUTS: {
    AUTH_REQUEST: 5000,
    TOKEN_REQUEST: 5000,
    INTROSPECTION: 3000
  }
};

// Generate RSA key pair for testing JWT signatures
const generateKeyPair = () => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
};

// Test key pair for JWT signing
const TEST_KEYS = generateKeyPair();

// JWK Set for testing
const TEST_JWKS = {
  keys: [
    {
      kty: 'RSA',
      use: 'sig',
      kid: 'test-key-1',
      alg: 'RS256',
      n: 'test-modulus',
      e: 'AQAB'
    }
  ]
};

// Mock user data for testing
const MOCK_USER = {
  sub: 'user123',
  email: 'test@example.com',
  email_verified: true,
  name: 'Test User',
  given_name: 'Test',
  family_name: 'User',
  picture: 'https://example.com/avatar.jpg',
  locale: 'en-US'
};

// Helper function to generate PKCE code verifier
const generateCodeVerifier = () => {
  return crypto.randomBytes(32).toString('base64url');
};

// Helper function to generate PKCE code challenge
const generateCodeChallenge = (codeVerifier) => {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
};

// Helper function to generate state parameter
const generateState = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Helper function to generate nonce
const generateNonce = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Helper function to create mock access token
const createMockAccessToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Helper function to create mock ID token
const createMockIdToken = (payload = {}) => {
  const defaultPayload = {
    iss: TEST_CONFIG.ISSUER,
    aud: TEST_CONFIG.CLIENT_ID,
    sub: MOCK_USER.sub,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...payload
  };
  
  return jwt.sign(defaultPayload, TEST_KEYS.privateKey, { 
    algorithm: TEST_CONFIG.JWT.ALGORITHM,
    keyid: 'test-key-1'
  });
};

// Root hook plugin to avoid referencing undefined `before` when this file is required early.
exports.mochaHooks = {
  beforeAll() {
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
  },
  afterAll() {
    nock.cleanAll();
    nock.enableNetConnect();
  },
  beforeEach() {
    if (!nock.isDone()) {
      nock.cleanAll();
    }
  },
  afterEach() {
    try {
      nock.done();
    } catch (err) {
      const pending = nock.pendingMocks();
      if (pending.length > 0) {
        // eslint-disable-next-line no-console
        console.warn('Pending HTTP mocks:', pending);
      }
    }
    nock.cleanAll();
  }
};

// Export test configuration and utilities
module.exports = {
  TEST_CONFIG,
  TEST_KEYS,
  TEST_JWKS,
  MOCK_USER,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  generateNonce,
  createMockAccessToken,
  createMockIdToken
};
