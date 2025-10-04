# OAuth 2.1 and OpenID Connect Test Suite

A comprehensive, standards-compliant test suite for OAuth 2.1 and OpenID Connect (OIDC) implementations using Node.js, Mocha, and Chai. This test suite is designed to be production-ready and covers all mandatory flows, security best practices, and edge cases defined in the latest specifications.

**Bootstrapped with assistance from Perplexity Labs**

## 🎯 Overview

This test suite validates OAuth 2.1 and OpenID Connect implementations against the following specifications:

- **OAuth 2.1**: [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- **OpenID Connect Core 1.0**: [openid-connect-core-1_0](https://openid.net/specs/openid-connect-core-1_0.html)
- **PKCE**: [RFC 7636 - Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636) (mandatory in OAuth 2.1)
- **OIDC Discovery 1.0**: [openid-connect-discovery-1_0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- **OIDC Dynamic Client Registration 1.0**: [openid-connect-registration-1_0](https://openid.net/specs/openid-connect-registration-1_0.html)
- **OAuth 2.0 Token Introspection**: [RFC 7662](https://tools.ietf.org/html/rfc7662)

## 📄 License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

This project was bootstrapped with assistance from **Perplexity Labs**, which helped accelerate the initial development and architecture design of this comprehensive OAuth 2.1 and OpenID Connect test suite.


## 🏗️ Architecture

```md
test/
├── oauth2_1/                    # OAuth 2.1 specific tests
│   ├── authorizationCodeFlow.js # Authorization Code + PKCE flow
│   ├── clientCredentialsFlow.js # Client Credentials grant
│   ├── refreshTokenRotation.js  # Refresh token rotation
│   ├── introspection.js         # Token introspection (RFC 7662)
│   └── security.js             # Security and edge cases
├── oidc/                       # OpenID Connect tests
│   ├── discovery.js            # OIDC Discovery 1.0
│   ├── dynamicRegistration.js  # Dynamic Client Registration
│   ├── authorizationCodeFlowPkce.js # OIDC Auth Code + PKCE
│   ├── userInfo.js            # UserInfo endpoint
│   ├── idTokenValidation.js   # ID Token validation
│   └── sessionManagement.js   # Session management
├── mocks/                      # Mock servers for testing
│   ├── mockAuthServer.js      # Mock Authorization Server
│   └── mockResourceServer.js  # Mock Resource Server
├── utils/                      # Utility functions
│   ├── tokenUtils.js          # Token creation and validation
│   └── cryptoUtils.js         # Cryptographic utilities
└── setup.js                   # Test configuration and setup
```

## ✨ Key Features

### OAuth 2.1 Compliance

- ✅ **Mandatory PKCE**: All authorization code flows require PKCE
- ✅ **Exact Redirect URI Matching**: No wildcards or substring matching
- ✅ **No Implicit Flow**: Removed for security reasons
- ✅ **No Password Grant**: Resource Owner Password Credentials removed
- ✅ **Refresh Token Rotation**: Mandatory for public clients
- ✅ **Bearer Tokens**: No tokens in query parameters

### OpenID Connect Support

- ✅ **ID Token Validation**: Complete JWT signature and claims validation
- ✅ **Discovery**: Well-known endpoint configuration validation
- ✅ **Dynamic Registration**: Client registration and management
- ✅ **UserInfo Endpoint**: Claims retrieval with proper scoping
- ✅ **Session Management**: Login and logout session handling

### Security Testing

- ✅ **PKCE Attack Prevention**: Code interception attack mitigation
- ✅ **CSRF Protection**: State parameter validation
- ✅ **Token Replay Prevention**: Single-use authorization codes
- ✅ **JWT Security**: Signature verification and claims validation
- ✅ **Rate Limiting**: Protection against brute force attacks
- ✅ **HTTPS Enforcement**: All endpoints require secure transport

## 🚀 Getting Started

### Prerequisites

- Node.js >= 16.0.0
- npm >= 8.0.0

### Installation

1. Clone or download this test suite:

```bash
git clone https://github.com/example/oauth2.1-oidc-test-suite.git
cd oauth2.1-oidc-test-suite
```

2. Install dependencies:

```bash
npm install
```

### Quick Start

Run all tests:

```bash
npm test
```

Run OAuth 2.1 tests only:

```bash
npm run test:oauth
```

Run OpenID Connect tests only:

```bash
npm run test:oidc
```

Run with coverage:

```bash
npm run test:coverage
```

## 🧪 Test Configuration

### Environment Setup

The test suite uses mock servers by default, but can be configured to test against real implementations:

```javascript
// test/setup.js
const TEST_CONFIG = {
  AUTH_SERVER_BASE_URL: 'https://your-auth-server.com',
  RESOURCE_SERVER_BASE_URL: 'https://your-api-server.com',
  CLIENT_ID: 'your-test-client-id',
  CLIENT_SECRET: 'your-test-client-secret',
  REDIRECT_URI: 'https://your-app.com/callback',
  // ... other configuration
};
```

### Mock Server Configuration

The included mock servers simulate a complete OAuth 2.1 and OIDC environment:

```javascript
const mockAuthServer = new MockAuthServer('https://auth.example.com');
mockAuthServer.setupAll(); // Sets up all endpoints

const mockResourceServer = new MockResourceServer('https://api.example.com');
mockResourceServer.setupCommonEndpoints();
```

## 📋 Test Categories

### OAuth 2.1 Tests

#### Authorization Code Flow (`authorizationCodeFlow.js`)

- PKCE requirement validation (S256 method mandatory)
- State parameter CSRF protection
- Exact redirect URI matching
- Authorization code expiration and single-use validation
- Token exchange with code_verifier validation

#### Client Credentials Flow (`clientCredentialsFlow.js`)

- Confidential client authentication
- Basic and POST authentication methods
- Scope validation and reduction
- Rate limiting and security measures

#### Token Introspection (`introspection.js`)

- Active/inactive token status validation
- RFC 7662 compliance testing
- Client authentication for introspection
- Token metadata and claims validation

### OpenID Connect Tests

#### Discovery (`discovery.js`)

- Well-known endpoint configuration validation
- Required and optional parameter validation
- OAuth 2.1 compatibility verification
- CORS and caching header validation

#### ID Token Validation (`idTokenValidation.js`)

- JWT structure and signature validation
- Claims validation (iss, aud, exp, nonce, etc.)
- JWKS integration and key rotation
- Security edge cases (algorithm confusion, clock skew)

#### Dynamic Registration (`dynamicRegistration.js`)

- Open and authenticated registration flows
- Client metadata validation
- Management operations (read, update, delete)
- Security and rate limiting

## 🔒 Security Test Coverage

The test suite includes comprehensive security testing:

### Attack Mitigation

- **Authorization Code Interception**: PKCE validation prevents code theft
- **CSRF Attacks**: State parameter validation
- **Token Replay**: Single-use authorization codes
- **JWT Attacks**: Signature validation and algorithm verification
- **Open Redirects**: Exact redirect URI matching

### Edge Cases

- Malformed requests and responses
- Clock skew tolerance
- Token expiration edge cases
- Key rotation scenarios
- Rate limiting effectiveness

## 🛠️ Customization

### Adding Custom Tests

Create new test files following the existing patterns:

```javascript
const { expect } = require('chai');
const MockAuthServer = require('../mocks/mockAuthServer');

describe('Custom OAuth 2.1 Feature', () => {
  let mockAuthServer;
  
  beforeEach(() => {
    mockAuthServer = new MockAuthServer('https://auth.example.com');
    mockAuthServer.setupAll();
  });

  afterEach(() => {
    mockAuthServer.cleanup();
  });

  it('should validate custom feature', async () => {
    // Your test implementation
  });
});
```

### Extending Mock Servers

Add custom endpoints to mock servers:

```javascript
// Extend MockAuthServer
mockAuthServer.scope
  .post('/custom-endpoint')
  .reply(200, { custom: 'response' });
```

### Configuration Options

Modify `test/setup.js` to customize:

- Test timeouts
- Default client configurations
- Key generation parameters
- Mock response data

## 📊 Test Reports

### Coverage Reports

Generate detailed coverage reports:

```bash
npm run test:coverage
```

This generates:

- Terminal summary
- HTML report in `coverage/lcov-report/index.html`
- JSON data in `coverage/coverage-final.json`

### Running Specific Test Suites

```bash
# Security-focused tests
npm run test:security

# Token introspection only
npm run test:introspection

# Watch mode for development
npm run test:watch
```

## 📚 Standards Compliance

This test suite ensures compliance with:

### OAuth 2.1 Requirements

- PKCE mandatory for all authorization code flows
- Exact redirect URI matching
- Removal of implicit and password grants
- Refresh token rotation for public clients
- HTTPS enforcement for all endpoints

### OpenID Connect Requirements

- ID token structure and validation
- Discovery endpoint functionality
- Dynamic client registration
- UserInfo endpoint security
- Session management capabilities

### Security Best Practices

- Token lifecycle management
- Cryptographic security requirements
- Attack prevention mechanisms
- Error handling and information disclosure

## 🤝 Contributing

1. Follow existing code patterns and testing conventions
2. Add comprehensive test coverage for new features
3. Update documentation for any configuration changes
4. Ensure all tests pass before submitting changes

### Development Guidelines

- Use descriptive test names that explain what is being validated
- Include comments explaining which specification requirements are being tested
- Mock external dependencies using nock
- Validate both success and error scenarios
- Test edge cases and security boundaries

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [OAuth 2.1 Draft Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

## 💡 Usage Examples

### Testing Your OAuth 2.1 Server

```javascript
// Configure for your server
const TEST_CONFIG = {
  AUTH_SERVER_BASE_URL: 'https://your-oauth-server.com',
  CLIENT_ID: 'test-client',
  CLIENT_SECRET: 'test-secret',
  REDIRECT_URI: 'https://client.example.com/callback'
};

// Run tests
npm test
```

### Validating OIDC Implementation

```javascript
// Test OIDC discovery
npm run test:oidc

// Test specific OIDC features
mocha test/oidc/idTokenValidation.js
mocha test/oidc/discovery.js
```

This test suite provides comprehensive validation for OAuth 2.1 and OpenID Connect implementations, ensuring security, standards compliance, and robust functionality.
