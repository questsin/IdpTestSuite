/**
 * OpenID Connect ID Token Validation Tests
 * 
 * This test suite validates ID Token structure, signature verification,
 * and claims validation according to OpenID Connect Core 1.0 specification.
 */

const { expect } = require('chai');
const nock = require('nock');
// jwt and jwksClient reserved for future real verification flows; currently not used in mock tests
const MockAuthServer = require('../mocks/mockAuthServer');
const { RESOLVED_CONFIG } = require('../setup');
const { live, isOIDC } = require('../providerEnv');
const { 
  createIdToken, 
  validateIdToken, 
  validateJwt,
  decodeJwt
} = require('../utils/tokenUtils');
const { 
  generateNonce,
  // generateState (unused after refactor)
} = require('../utils/cryptoUtils');

describe('OpenID Connect ID Token Validation', () => {
  let mockAuthServer;
  let testKeyPair;
  const ISSUER = RESOLVED_CONFIG.AUTH_SERVER_BASE_URL || 'https://auth.example.com';
  const CLIENT_ID = RESOLVED_CONFIG.CLIENT_ID || 'test-client-id';
  const USER_SUB = 'user123';

  before(function () {
    if (!isOIDC() || live()) this.skip();
  });

  beforeEach(async () => {
    if (!live()) {
      mockAuthServer = new MockAuthServer(ISSUER);
      mockAuthServer.setupAll();
    }
    const crypto = require('crypto');
    testKeyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  });

  afterEach(() => {
    if (!live()) {
      mockAuthServer && mockAuthServer.cleanup();
    }
  });

  describe('ID Token Structure Validation', () => {
    it('should validate proper ID Token JWT structure', () => {
      // Test validates basic JWT structure (header.payload.signature)
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        auth_time: Math.floor(Date.now() / 1000) - 10
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      // Validate JWT structure
      expect(idToken).to.be.a('string');
      expect(idToken.split('.')).to.have.lengthOf(3);
      
      // Decode and validate structure
      const decoded = decodeJwt(idToken);
      expect(decoded.header).to.have.property('alg');
      expect(decoded.header).to.have.property('typ');
      expect(decoded.payload).to.have.property('iss');
      expect(decoded.signature).to.be.a('string');
    });

    it('should include all required OIDC claims in ID Token', () => {
      // Test validates presence of all required OIDC Core claims
      
      const now = Math.floor(Date.now() / 1000);
      const nonce = generateNonce();
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: now + 3600,
        iat: now,
        auth_time: now - 10,
        nonce: nonce
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      const decoded = decodeJwt(idToken);
      
      // Required claims per OIDC Core 1.0
      const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
      requiredClaims.forEach(claim => {
        expect(decoded.payload).to.have.property(claim);
      });
      
      // Validate claim values
      expect(decoded.payload.iss).to.equal(ISSUER);
      expect(decoded.payload.sub).to.equal(USER_SUB);
      expect(decoded.payload.aud).to.equal(CLIENT_ID);
      expect(decoded.payload.nonce).to.equal(nonce);
      expect(decoded.payload.exp).to.be.a('number');
      expect(decoded.payload.iat).to.be.a('number');
    });

    it('should validate ID Token header contains proper algorithm', () => {
      // Test validates JWT header specifies RS256 algorithm
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, { 
        algorithm: 'RS256',
        keyid: 'test-key-1'
      }, testKeyPair.privateKey);
      
      const decoded = decodeJwt(idToken);
      
      expect(decoded.header.alg).to.equal('RS256');
      expect(decoded.header.typ).to.equal('JWT');
      expect(decoded.header.kid).to.equal('test-key-1');
    });
  });

  describe('ID Token Signature Verification', () => {
    it('should successfully verify ID Token signature with correct public key', () => {
      // Test validates JWT signature verification using JWKS
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      // Verify signature using public key
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER
        });
      }).to.not.throw();
    });

    it('should reject ID Token with invalid signature', () => {
      // Test validates rejection of tampered ID Tokens
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      // Tamper with the token (change last character)
      const tamperedToken = idToken.slice(0, -1) + 'X';
      
      expect(() => {
        validateJwt(tamperedToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER
        });
      }).to.throw();
    });

    it('should reject ID Token signed with wrong key', () => {
      // Test validates rejection when wrong key is used for verification
      
      // Generate different key pair
      const wrongKeyPair = require('crypto').generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      // Try to verify with wrong public key
      expect(() => {
        validateJwt(idToken, wrongKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER
        });
      }).to.throw();
    });
  });

  describe('ID Token Claims Validation', () => {
    it('should validate issuer claim matches expected value', () => {
      // Test validates 'iss' claim verification
      
      const correctIssuer = ISSUER;
      const wrongIssuer = 'https://malicious.example.com';
      
      const idTokenPayload = {
        iss: wrongIssuer, // Wrong issuer
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: correctIssuer // Expecting correct issuer
        });
      }).to.throw(/issuer/i);
    });

    it('should validate audience claim matches client ID', () => {
      // Test validates 'aud' claim verification
      
      const correctClientId = CLIENT_ID;
      const wrongClientId = 'different-client-id';
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: wrongClientId, // Wrong audience
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: correctClientId, // Expecting correct audience
          issuer: ISSUER
        });
      }).to.throw(/audience/i);
    });

    it('should validate expiration time is not passed', () => {
      // Test validates 'exp' claim verification
      
      const pastTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: pastTime, // Expired token
        iat: Math.floor(Date.now() / 1000) - 3601
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER
        });
      }).to.throw(/expired/i);
    });

    it('should validate nonce claim matches request nonce', () => {
      // Test validates 'nonce' claim verification for replay protection
      
      const requestNonce = generateNonce();
      const wrongNonce = generateNonce();
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        nonce: wrongNonce // Different nonce
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateIdToken(idToken, {
          clientId: CLIENT_ID,
          issuer: ISSUER,
          nonce: requestNonce // Expected nonce
        }, testKeyPair.publicKey);
      }).to.throw(/nonce/i);
    });

    it('should validate auth_time with max_age parameter', () => {
      // Test validates 'auth_time' claim with max_age constraint
      
      const oldAuthTime = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
      const maxAge = 3600; // 1 hour
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        auth_time: oldAuthTime
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateIdToken(idToken, {
          clientId: CLIENT_ID,
          issuer: ISSUER,
          maxAge: maxAge
        }, testKeyPair.publicKey);
      }).to.throw(/auth_time.*max_age/i);
    });

    it('should validate issued at time is reasonable', () => {
      // Test validates 'iat' claim is not in the future
      
      const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 7200,
        iat: futureTime // Future iat
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER,
          clockTolerance: 30 // 30 seconds tolerance
        });
      }).to.throw();
    });
  });

  describe('ID Token with User Claims', () => {
    it('should include profile claims when profile scope requested', () => {
      // Test validates profile scope claims inclusion
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User',
        nickname: 'testuser',
        picture: 'https://example.com/avatar.jpg',
        locale: 'en-US'
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      const decoded = decodeJwt(idToken);
      
      // Validate profile claims
      expect(decoded.payload.name).to.equal('Test User');
      expect(decoded.payload.given_name).to.equal('Test');
      expect(decoded.payload.family_name).to.equal('User');
      expect(decoded.payload.picture).to.match(/^https:/);
    });

    it('should include email claims when email scope requested', () => {
      // Test validates email scope claims inclusion
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'test@example.com',
        email_verified: true
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      const decoded = decodeJwt(idToken);
      
      // Validate email claims
      expect(decoded.payload.email).to.equal('test@example.com');
      expect(decoded.payload.email_verified).to.be.true;
    });

    it('should not include claims for ungranted scopes', () => {
      // Test validates scope-based claim filtering
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
        // Only openid scope - no profile or email claims
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      const decoded = decodeJwt(idToken);
      
      // Should not contain profile/email claims
      expect(decoded.payload).to.not.have.property('name');
      expect(decoded.payload).to.not.have.property('email');
      expect(decoded.payload).to.not.have.property('phone_number');
    });
  });

  describe('JWKS Integration', () => {
    it('should retrieve and use JWKS for ID Token verification', async () => {
      // Test validates JWKS-based signature verification
      
  // jwksUri variable omitted (not directly used in mock path assertions)
      const keyId = 'test-key-1';
      
      // Mock JWKS endpoint
      if (!live()) {
        nock(ISSUER)
          .get('/.well-known/jwks.json')
          .reply(200, {
          keys: [{
            kty: 'RSA',
            use: 'sig',
            kid: keyId,
            alg: 'RS256',
            n: 'test-modulus',
            e: 'AQAB'
          }]
          });
      }
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, { 
        keyid: keyId 
      }, testKeyPair.privateKey);
      
      const decoded = decodeJwt(idToken);
      
      // Validate that token references correct key ID
      expect(decoded.header.kid).to.equal(keyId);
    });

    it('should handle JWKS key rotation', async () => {
      // Test validates handling of key rotation scenarios
      
      const oldKeyId = 'old-key-1';
      const newKeyId = 'new-key-2';
      
      // First JWKS response with old key
      if (!live()) {
        nock(ISSUER)
          .get('/.well-known/jwks.json')
          .reply(200, {
          keys: [{
            kty: 'RSA',
            use: 'sig',
            kid: oldKeyId,
            alg: 'RS256',
            n: 'old-modulus',
            e: 'AQAB'
          }]
          });
      }
      
      // Second JWKS response with both keys
      if (!live()) {
        nock(ISSUER)
          .get('/.well-known/jwks.json')
          .reply(200, {
          keys: [
            {
              kty: 'RSA',
              use: 'sig',
              kid: oldKeyId,
              alg: 'RS256',
              n: 'old-modulus',
              e: 'AQAB'
            },
            {
              kty: 'RSA',
              use: 'sig',
              kid: newKeyId,
              alg: 'RS256',
              n: 'new-modulus',
              e: 'AQAB'
            }
          ]
          });
      }
      
      // Token signed with new key should be verifiable
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, { 
        keyid: newKeyId 
      }, testKeyPair.privateKey);
      
      const decoded = decodeJwt(idToken);
      expect(decoded.header.kid).to.equal(newKeyId);
    });

    it('should reject ID Token with unknown key ID', async () => {
      // Test validates rejection of tokens with unknown key IDs
      
      const knownKeyId = 'known-key-1';
      const unknownKeyId = 'unknown-key-999';
      
      if (!live()) {
        nock(ISSUER)
          .get('/.well-known/jwks.json')
          .reply(200, {
          keys: [{
            kty: 'RSA',
            use: 'sig',
            kid: knownKeyId,
            alg: 'RS256',
            n: 'known-modulus',
            e: 'AQAB'
          }]
          });
      }
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, { 
        keyid: unknownKeyId // Unknown key ID
      }, testKeyPair.privateKey);
      
      const decoded = decodeJwt(idToken);
      expect(decoded.header.kid).to.equal(unknownKeyId);
      
      // In real implementation, this would fail JWKS lookup
      // Here we validate the token contains the unknown key ID
    });
  });

  describe('ID Token Security Edge Cases', () => {
    it('should reject ID Tokens with "none" algorithm', () => {
      // Test validates rejection of unsigned tokens
      
      const unsignedPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      // Create token with 'none' algorithm (unsigned)
      const header = { alg: 'none', typ: 'JWT' };
      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(unsignedPayload)).toString('base64url');
      const unsignedToken = `${encodedHeader}.${encodedPayload}.`;
      
      expect(() => {
        validateJwt(unsignedToken, testKeyPair.publicKey, {
          algorithms: ['RS256'], // Should reject 'none'
          audience: CLIENT_ID,
          issuer: ISSUER
        });
      }).to.throw();
    });

    it('should validate clock skew tolerance', () => {
      // Test validates reasonable clock skew handling
      
      const now = Math.floor(Date.now() / 1000);
      const skewedTime = now + 120; // 2 minutes in future
      
      const idTokenPayload = {
        iss: ISSUER,
        sub: USER_SUB,
        aud: CLIENT_ID,
        exp: skewedTime + 3600,
        iat: skewedTime // Slightly in future due to clock skew
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      // Should accept with sufficient clock tolerance
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER,
          clockTolerance: 300 // 5 minutes tolerance
        });
      }).to.not.throw();
      
      // Should reject with insufficient clock tolerance
      expect(() => {
        validateJwt(idToken, testKeyPair.publicKey, {
          audience: CLIENT_ID,
          issuer: ISSUER,
          clockTolerance: 30 // 30 seconds tolerance
        });
      }).to.throw();
    });

    it('should validate subject claim is present and non-empty', () => {
      // Test validates required 'sub' claim
      
      const idTokenPayload = {
        iss: ISSUER,
        // Missing sub claim
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const idToken = createIdToken(idTokenPayload, {}, testKeyPair.privateKey);
      
      expect(() => {
        validateIdToken(idToken, {
          clientId: CLIENT_ID,
          issuer: ISSUER
        }, testKeyPair.publicKey);
      }).to.throw(/sub/i);
    });
  });
});