# WP REST Auth Multi - Testing Guide

This document provides comprehensive information about testing the WP REST Auth Multi plugin using wp-env and PHPUnit.

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm 8+
- Docker and Docker Compose
- Composer

### Setup

1. **Install dependencies**:
   ```bash
   npm install
   composer install
   ```

2. **Start the WordPress environment**:
   ```bash
   npm run env:start
   ```

3. **Run tests**:
   ```bash
   npm run test
   ```

## 🛠️ Testing Environment

### wp-env Configuration

The testing environment is configured in `.wp-env.json`:

- **WordPress**: Version 6.4 (configurable)
- **PHP**: Latest stable version in Docker
- **Database**: MySQL (handled automatically by wp-env)
- **Plugins**: Our plugin is automatically loaded
- **Theme**: Twenty Twenty-Four

### Environment URLs

- **Development site**: http://localhost:8888
- **Test site**: http://localhost:8889
- **Admin**: http://localhost:8888/wp-admin (admin/password)

## 🧪 Test Structure

### Test Suites

#### Unit Tests (`tests/unit/`)
- **AuthJWTTest.php**: JWT authentication functionality
- **AuthOAuth2Test.php**: OAuth2 authentication flows
- **AdminSettingsTest.php**: Admin settings and configuration

#### Integration Tests (`tests/integration/`)
- **RestApiEndpointsTest.php**: REST API endpoint testing with WordPress

### Test Helpers (`tests/helpers/`)
- **TestCase.php**: Base test case with common utilities
- **MockFactory.php**: Factory for creating mock data and objects

## 📋 Available Commands

### Environment Management
```bash
# Start the environment
npm run env:start

# Stop the environment
npm run env:stop

# Clean/reset the environment
npm run env:clean

# Destroy the environment
npm run env:destroy
```

### Testing Commands
```bash
# Run all tests
npm run test

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Generate coverage reports
npm run test:coverage

# Watch mode (re-run tests on file changes)
npm run test:watch
```

### Composer Commands (via wp-env)
```bash
# Install/update PHP dependencies in the container
npm run composer:install
npm run composer:update
```

## 🔧 Test Configuration

### PHPUnit Configuration (`phpunit.xml`)

The PHPUnit configuration is optimized for wp-env:

- **Bootstrap**: `tests/bootstrap-wp-env.php`
- **Test Suites**: `unit` and `integration`
- **Coverage**: HTML reports in `tests/coverage/html/`
- **Environment**: Uses wp-env WordPress installation

### Test Constants

The following constants are automatically defined for testing:

```php
define('WP_JWT_AUTH_SECRET', 'test-secret-key...');
define('WP_JWT_ACCESS_TTL', 3600);
define('WP_JWT_REFRESH_TTL', 86400);
```

## 📊 Test Coverage

### What's Tested

#### JWT Authentication
- ✅ Token generation and validation
- ✅ Token expiration handling
- ✅ Refresh token functionality
- ✅ Bearer token authentication
- ✅ Login/refresh/validate endpoints
- ✅ Security validation (invalid tokens, expired tokens)

#### OAuth2 Authentication
- ✅ Client validation and management
- ✅ Authorization code flow (PKCE)
- ✅ Access token generation and validation
- ✅ Scope validation and enforcement
- ✅ Redirect URI validation
- ✅ State parameter validation
- ✅ User consent handling
- ✅ Userinfo endpoint

#### Admin Settings
- ✅ Settings sanitization and validation
- ✅ OAuth2 client CRUD operations
- ✅ JWT configuration management
- ✅ AJAX handlers for client management
- ✅ Security (nonce validation, capability checks)
- ✅ UI rendering (form fields, tabs)

#### REST API Integration
- ✅ Endpoint registration
- ✅ Request/response handling
- ✅ Error handling and validation
- ✅ CORS handling
- ✅ Bearer token authentication
- ✅ Scope enforcement

### Coverage Reports

Generate and view coverage reports:

```bash
npm run test:coverage
open tests/coverage/html/index.html
```

## 🐛 Debugging Tests

### Enable Debug Output

1. **WordPress Debug Logging**: Already enabled in wp-env
2. **PHPUnit Verbose Mode**: Enabled by default in `phpunit.xml`
3. **Plugin Debug Logging**: Controlled by admin settings

### Debug Information

The bootstrap file outputs useful information:
- WordPress version
- PHP version
- Test directory paths
- Plugin loading status

### Debugging Failed Tests

1. **Check wp-env logs**:
   ```bash
   wp-env logs
   ```

2. **Run specific test**:
   ```bash
   npm run test -- --filter=testMethodName
   ```

3. **Enable WordPress debugging**:
   ```bash
   wp-env run wordpress wp config set WP_DEBUG true --raw
   wp-env run wordpress wp config set WP_DEBUG_LOG true --raw
   ```

## 🔍 Writing Tests

### Test Class Structure

```php
<?php
namespace WPRestAuthMulti\Tests\Unit;

use WPRestAuthMulti\Tests\Helpers\TestCase;
use WPRestAuthMulti\Tests\Helpers\MockFactory;

class MyFeatureTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Setup test-specific conditions
    }

    public function testMyFeature(): void
    {
        // Arrange
        $mock_data = MockFactory::createMockUser();

        // Act
        $result = $this->my_plugin_method($mock_data);

        // Assert
        $this->assertTrue($result);
    }
}
```

### Best Practices

1. **Use MockFactory**: Create consistent mock data
2. **Test Edge Cases**: Invalid input, expired tokens, etc.
3. **Mock WordPress Functions**: Use the provided helper methods
4. **Clean State**: Each test should be independent
5. **Descriptive Names**: Use clear, descriptive test method names

### Mock Data Examples

```php
// Create mock user
$user = MockFactory::createMockWPUser(123, 'testuser');

// Create mock OAuth2 client
$client = MockFactory::createMockOAuth2Client('test-client');

// Create mock JWT token
$token = $this->createTestJWT(123);

// Create mock HTTP request
$request = MockFactory::createMockWPRestRequest('POST', '/endpoint');
```

## 📚 Testing Scenarios

### Authentication Flows

1. **JWT Login Flow**:
   - Valid credentials → Access + refresh tokens
   - Invalid credentials → Error response
   - Missing fields → Validation error

2. **Token Refresh Flow**:
   - Valid refresh token → New access token
   - Invalid/expired refresh token → Error
   - Missing refresh token → Validation error

3. **OAuth2 Authorization Flow**:
   - Client validation → Authorization code
   - Code exchange → Access token
   - Scope enforcement → Permission checks

### Security Tests

1. **Token Security**:
   - Expired token rejection
   - Invalid signature detection
   - Token tampering protection

2. **OAuth2 Security**:
   - PKCE validation
   - State parameter verification
   - Redirect URI validation
   - Scope enforcement

3. **Input Validation**:
   - SQL injection prevention
   - XSS protection
   - Invalid parameter handling

## 🚨 Troubleshooting

### Common Issues

1. **wp-env not starting**:
   ```bash
   wp-env destroy
   wp-env start
   ```

2. **Tests not finding WordPress**:
   - Ensure wp-env is running: `wp-env status`
   - Check bootstrap file paths

3. **Database connection issues**:
   ```bash
   wp-env clean
   npm run composer:install
   ```

4. **Permission errors**:
   ```bash
   sudo chown -R $(whoami) .
   ```

### Reset Environment

Complete reset if you encounter persistent issues:

```bash
wp-env destroy
rm -rf node_modules vendor
npm install
composer install
npm run env:start
npm run test
```

## 📈 Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - name: Install dependencies
        run: |
          npm install
          composer install

      - name: Start wp-env
        run: npm run env:start

      - name: Run tests
        run: npm run test:coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## 📖 Additional Resources

- [wp-env Documentation](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-env/)
- [PHPUnit Documentation](https://phpunit.de/documentation.html)
- [WordPress Plugin Testing](https://make.wordpress.org/core/handbook/testing/automated-testing/phpunit/)
- [JWT Testing Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [OAuth2 Testing Guide](https://datatracker.ietf.org/doc/html/rfc6749#section-10)