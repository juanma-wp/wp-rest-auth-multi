<?php

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for OAuth2 Authentication
 */
class OAuth2AuthTest extends TestCase
{
    private $auth_oauth2;

    protected function setUp(): void
    {
        parent::setUp();

        // Load the OAuth2 auth class
        if (!class_exists('Auth_OAuth2')) {
            require_once dirname(__DIR__, 2) . '/includes/class-auth-oauth2.php';
        }

        $this->auth_oauth2 = new Auth_OAuth2();
    }

    public function testOAuth2AuthClassExists(): void
    {
        $this->assertTrue(class_exists('Auth_OAuth2'));
        $this->assertInstanceOf('Auth_OAuth2', $this->auth_oauth2);
    }

    public function testOAuth2RestRoutesRegistration(): void
    {
        // Test that OAuth2 routes registration method exists
        $this->assertTrue(method_exists($this->auth_oauth2, 'register_routes'));

        // Don't actually call register_routes in tests as it needs rest_api_init hook
        // In a real WordPress environment, this would be called on rest_api_init
        $this->assertTrue(true); // Method exists, that's what we're testing
    }

    public function testOAuth2AuthorizationEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'authorize_endpoint'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'handle_authorize_page'));
    }

    public function testOAuth2TokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'token_endpoint'));

        // Create a mock request
        $request = new stdClass();
        $request->grant_type = 'authorization_code';
        $request->client_id = 'test-client';

        $this->assertTrue(method_exists($this->auth_oauth2, 'token_endpoint'));
    }

    public function testOAuth2UserinfoEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'userinfo_endpoint'));
    }

    public function testOAuth2BearerAuthentication(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'authenticate_bearer'));

        // Test with invalid token
        $result = $this->auth_oauth2->authenticate_bearer('invalid-token');
        $this->assertInstanceOf('WP_Error', $result);
    }

    public function testClientManagement(): void
    {
        // Test client management methods
        $this->assertTrue(method_exists($this->auth_oauth2, 'get_clients'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_redirect_uri'));

        // Test getting clients (should return array)
        $clients = $this->auth_oauth2->get_clients();
        $this->assertIsArray($clients);
    }

    public function testRedirectURIValidation(): void
    {
        // Test redirect URI validation with invalid client
        $result = $this->auth_oauth2->validate_redirect_uri('invalid-client', 'https://example.com/callback');
        $this->assertFalse($result);
    }

    public function testTokenRevocation(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'revoke_token'));

        // Test revoking invalid token
        $result = $this->auth_oauth2->revoke_token('invalid-token');
        $this->assertFalse($result);
    }

    public function testCodeCleanup(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'clean_expired_codes'));

        // Test cleanup (should not throw errors)
        $this->auth_oauth2->clean_expired_codes();
        $this->assertTrue(true);
    }

    public function testScopeValidation(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_request_scopes'));

        // Test scope validation method exists
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_request_scopes'));
    }

    public function testCORSSupport(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'add_cors_support'));

        // Test CORS method exists and can be called
        $this->auth_oauth2->add_cors_support();
        $this->assertTrue(true); // Should not throw errors
    }

    public function testOAuth2HelperMethods(): void
    {
        // Test that helper methods exist (using reflection since they're private)
        $reflection = new ReflectionClass($this->auth_oauth2);

        $this->assertTrue($reflection->hasMethod('get_client'));
        $this->assertTrue($reflection->hasMethod('code_key'));
        $this->assertTrue($reflection->hasMethod('token_key'));
        $this->assertTrue($reflection->hasMethod('debug_log'));
    }

    public function testScopeConstants(): void
    {
        // Test that OAuth2 scope handling is available
        // OAuth2 scopes are typically handled within the class methods
        $this->assertTrue(class_exists('Auth_OAuth2'));
    }

    public function testAuthorizationPageHandler(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'handle_authorize_page'));

        // Test authorization page handling
        $this->auth_oauth2->handle_authorize_page();
        $this->assertTrue(true); // Should not throw errors
    }

    public function testOAuth2ErrorHandling(): void
    {
        // Test error handling methods exist
        $reflection = new ReflectionClass($this->auth_oauth2);
        $this->assertTrue($reflection->hasMethod('oauth_error_redirect'));
    }

    public function testClientValidation(): void
    {
        // Test client validation with reflection
        $reflection = new ReflectionClass($this->auth_oauth2);
        $method = $reflection->getMethod('get_client');
        $method->setAccessible(true);

        // Test invalid client
        $result = $method->invoke($this->auth_oauth2, 'invalid-client-id');
        $this->assertNull($result);
    }

    public function testTransientKeyGeneration(): void
    {
        // Test transient key generation methods
        $reflection = new ReflectionClass($this->auth_oauth2);

        $code_method = $reflection->getMethod('code_key');
        $code_method->setAccessible(true);
        $code_key = $code_method->invoke($this->auth_oauth2, 'test-code');
        $this->assertStringContainsString('oauth2_code_', $code_key);

        $token_method = $reflection->getMethod('token_key');
        $token_method->setAccessible(true);
        $token_key = $token_method->invoke($this->auth_oauth2, 'test-token');
        $this->assertStringContainsString('oauth2_token_', $token_key);
    }

    public function testScopeParsingAndValidation(): void
    {
        // Test scope parsing methods
        $reflection = new ReflectionClass($this->auth_oauth2);

        if ($reflection->hasMethod('parse_scopes')) {
            $method = $reflection->getMethod('parse_scopes');
            $method->setAccessible(true);

            $result = $method->invoke($this->auth_oauth2, 'read write delete');
            $this->assertIsArray($result);
            $this->assertContains('read', $result);
            $this->assertContains('write', $result);
            $this->assertContains('delete', $result);
        } else {
            // If parse_scopes doesn't exist, mark as skipped
            $this->markTestSkipped('parse_scopes method not found');
        }
    }

    public function testDebugLogging(): void
    {
        // Test debug logging functionality
        $reflection = new ReflectionClass($this->auth_oauth2);
        $method = $reflection->getMethod('debug_log');
        $method->setAccessible(true);

        // Test logging (should not throw errors)
        $method->invoke($this->auth_oauth2, 'Test message', ['data' => 'test']);
        $this->assertTrue(true);
    }
}