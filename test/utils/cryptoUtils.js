/**
 * Cryptographic Utilities for OAuth 2.1 and OIDC Testing
 * 
 * This module provides cryptographic functions required for
 * PKCE, JWK handling, and other security operations.
 */

const crypto = require('crypto');
const { promisify } = require('util');
const jose = require('node-jose');

/**
 * Generate PKCE code verifier according to RFC 7636
 * Uses cryptographically secure random values
 * @param {number} length - Length between 43-128 characters
 * @returns {string} Base64URL-encoded code verifier
 */
const generateCodeVerifier = (length = 64) => {
  if (length < 43 || length > 128) {
    throw new Error('PKCE code verifier length must be between 43 and 128 characters');
  }
  
  // Generate random bytes and encode as base64url
  const buffer = crypto.randomBytes(Math.ceil(length * 3 / 4));
  return buffer.toString('base64url').substring(0, length);
};

/**
 * Generate PKCE code challenge from code verifier
 * @param {string} codeVerifier - Code verifier string
 * @param {string} method - Challenge method ('plain' or 'S256')
 * @returns {string} Code challenge
 */
const generateCodeChallenge = (codeVerifier, method = 'S256') => {
  if (method === 'plain') {
    // OAuth 2.1 deprecates 'plain' method, but included for completeness
    console.warn('WARNING: Plain PKCE method is deprecated in OAuth 2.1');
    return codeVerifier;
  }
  
  if (method === 'S256') {
    return crypto
      .createHash('sha256')
      .update(codeVerifier, 'ascii')
      .digest('base64url');
  }
  
  throw new Error(`Unsupported PKCE code challenge method: ${method}`);
};

/**
 * Verify PKCE code challenge matches code verifier
 * @param {string} codeVerifier - Original code verifier
 * @param {string} codeChallenge - Code challenge to verify
 * @param {string} method - Challenge method used
 * @returns {boolean} True if verification succeeds
 */
const verifyCodeChallenge = (codeVerifier, codeChallenge, method = 'S256') => {
  try {
    const expectedChallenge = generateCodeChallenge(codeVerifier, method);
    return crypto.timingSafeEqual(
      Buffer.from(expectedChallenge),
      Buffer.from(codeChallenge)
    );
  } catch (error) {
    return false;
  }
};

/**
 * Generate cryptographically secure state parameter
 * @param {number} length - Byte length for state parameter
 * @returns {string} Hex-encoded state parameter
 */
const generateState = (length = 16) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate cryptographically secure nonce for OIDC
 * @param {number} length - Byte length for nonce
 * @returns {string} Base64URL-encoded nonce
 */
const generateNonce = (length = 16) => {
  return crypto.randomBytes(length).toString('base64url');
};

/**
 * Create RSA key pair for JWT signing
 * @param {number} modulusLength - RSA key size in bits
 * @returns {Object} Key pair with public and private keys
 */
const generateRsaKeyPair = async (modulusLength = 2048) => {
  const generateKeyPair = promisify(crypto.generateKeyPair);
  
  return await generateKeyPair('rsa', {
    modulusLength,
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

/**
 * Convert PEM public key to JWK format
 * @param {string} pemKey - PEM-formatted public key
 * @param {string} keyId - Key identifier
 * @param {string} use - Key use ('sig' or 'enc')
 * @returns {Object} JWK representation
 */
const pemToJwk = async (pemKey, keyId = 'test-key', use = 'sig') => {
  const key = await jose.JWK.asKey(pemKey, 'pem');
  const jwk = key.toJSON();
  
  return {
    ...jwk,
    kid: keyId,
    use: use,
    alg: use === 'sig' ? 'RS256' : 'RSA-OAEP'
  };
};

/**
 * Create JWK Set (JWKS) from multiple keys
 * @param {Array} keys - Array of JWK objects
 * @returns {Object} JWK Set
 */
const createJwks = (keys) => {
  return {
    keys: Array.isArray(keys) ? keys : [keys]
  };
};

/**
 * Generate symmetric key for HMAC operations
 * @param {number} length - Key length in bytes
 * @returns {string} Base64-encoded symmetric key
 */
const generateSymmetricKey = (length = 32) => {
  return crypto.randomBytes(length).toString('base64');
};

/**
 * Create HMAC signature for client authentication
 * @param {string} data - Data to sign
 * @param {string} secret - Client secret
 * @param {string} algorithm - HMAC algorithm (default: sha256)
 * @returns {string} Base64-encoded HMAC signature
 */
const createHmacSignature = (data, secret, algorithm = 'sha256') => {
  return crypto
    .createHmac(algorithm, secret)
    .update(data)
    .digest('base64');
};

/**
 * Verify HMAC signature
 * @param {string} data - Original data
 * @param {string} signature - Signature to verify
 * @param {string} secret - Secret key
 * @param {string} algorithm - HMAC algorithm
 * @returns {boolean} Verification result
 */
const verifyHmacSignature = (data, signature, secret, algorithm = 'sha256') => {
  const expectedSignature = createHmacSignature(data, secret, algorithm);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'base64'),
    Buffer.from(expectedSignature, 'base64')
  );
};

/**
 * Generate client credentials for testing
 * @returns {Object} Client ID and secret pair
 */
const generateClientCredentials = () => {
  return {
    client_id: `client_${crypto.randomBytes(8).toString('hex')}`,
    client_secret: crypto.randomBytes(32).toString('base64url')
  };
};

/**
 * Create basic authentication header
 * @param {string} clientId - Client identifier
 * @param {string} clientSecret - Client secret
 * @returns {string} Basic auth header value
 */
const createBasicAuthHeader = (clientId, clientSecret) => {
  const credentials = `${clientId}:${clientSecret}`;
  return `Basic ${Buffer.from(credentials).toString('base64')}`;
};

/**
 * Hash password using PBKDF2 (for test user accounts)
 * @param {string} password - Plain text password
 * @param {string} salt - Salt value
 * @param {number} iterations - PBKDF2 iterations
 * @returns {string} Hashed password
 */
const hashPassword = (password, salt = null, iterations = 10000) => {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, actualSalt, iterations, 64, 'sha512');
  return `${actualSalt}:${hash.toString('hex')}`;
};

/**
 * Verify password against hash
 * @param {string} password - Plain text password
 * @param {string} hashedPassword - Stored hash
 * @param {number} iterations - PBKDF2 iterations
 * @returns {boolean} Verification result
 */
const verifyPassword = (password, hashedPassword, iterations = 10000) => {
  const [salt, hash] = hashedPassword.split(':');
  const newHash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), newHash);
};

/**
 * Generate secure random string for various purposes
 * @param {number} length - String length
 * @param {string} charset - Character set to use
 * @returns {string} Random string
 */
const generateRandomString = (length = 32, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') => {
  let result = '';
  const bytes = crypto.randomBytes(length);
  
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  
  return result;
};

module.exports = {
  generateCodeVerifier,
  generateCodeChallenge,
  verifyCodeChallenge,
  generateState,
  generateNonce,
  generateRsaKeyPair,
  pemToJwk,
  createJwks,
  generateSymmetricKey,
  createHmacSignature,
  verifyHmacSignature,
  generateClientCredentials,
  createBasicAuthHeader,
  hashPassword,
  verifyPassword,
  generateRandomString
};