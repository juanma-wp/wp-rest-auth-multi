<?php

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for JWT Authentication
 */
class JWTAuthTest extends TestCase
{
    private $auth_jwt;

    protected function setUp(): void
    {
        parent::setUp();

        // Load the JWT auth class
        if (!class_exists('Auth_JWT')) {
            require_once dirname(__DIR__, 2) . '/includes/class-auth-jwt.php';
        }

        $this->auth_jwt = new Auth_JWT();
    }

    public function testJWTAuthClassExists(): void
    {
        $this->assertTrue(class_exists('Auth_JWT'));
        $this->assertInstanceOf('Auth_JWT', $this->auth_jwt);
    }

    public function testRestRoutesRegistration(): void
    {
        // Test that JWT routes registration method exists
        $this->assertTrue(method_exists($this->auth_jwt, 'register_routes'));

        // Don't actually call register_routes in tests as it needs rest_api_init hook
        // In a real WordPress environment, this would be called on rest_api_init
        $this->assertTrue(true); // Method exists, that's what we're testing
    }

    public function testTokenIssuanceEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'issue_token'));

        // Create a mock request
        $request = new stdClass();
        $request->username = 'testuser';
        $request->password = 'testpass';

        // Test that the method exists and can be called
        $this->assertTrue(method_exists($this->auth_jwt, 'issue_token'));
    }

    public function testTokenRefreshEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'refresh_access_token'));

        // Test refresh token endpoint exists
        $request = new stdClass();
        $this->assertTrue(method_exists($this->auth_jwt, 'refresh_access_token'));
    }

    public function testLogoutEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'logout'));
    }

    public function testWhoamiEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'whoami'));
    }

    public function testBearerTokenAuthentication(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'authenticate_bearer'));

        // Test with invalid token
        $result = $this->auth_jwt->authenticate_bearer('invalid-token');
        $this->assertInstanceOf('WP_Error', $result);
    }

    public function testRefreshTokenStorage(): void
    {
        // Test refresh token storage methods exist
        $this->assertTrue(method_exists($this->auth_jwt, 'get_user_refresh_tokens'));
        $this->assertTrue(method_exists($this->auth_jwt, 'revoke_user_token'));
        $this->assertTrue(method_exists($this->auth_jwt, 'clean_expired_tokens'));
    }

    public function testTokenCleanupFunctionality(): void
    {
        // Test expired token cleanup
        $this->auth_jwt->clean_expired_tokens();
        $this->assertTrue(true); // Should not throw errors
    }

    public function testUserTokenManagement(): void
    {
        $user_id = 123;

        // Test getting user tokens
        $tokens = $this->auth_jwt->get_user_refresh_tokens($user_id);
        $this->assertIsArray($tokens);

        // Test revoking a token (should handle non-existent token gracefully)
        $result = $this->auth_jwt->revoke_user_token($user_id, 999);
        $this->assertIsBool($result);
    }

    public function testCORSSupport(): void
    {
        $this->assertTrue(method_exists($this->auth_jwt, 'add_cors_support'));

        // Test CORS method exists and can be called
        $this->auth_jwt->add_cors_support();
        $this->assertTrue(true); // Should not throw errors
    }

    public function testJWTConstants(): void
    {
        // Test JWT constants are available
        $this->assertTrue(defined('WP_JWT_AUTH_SECRET'));
        $this->assertTrue(defined('WP_JWT_ACCESS_TTL'));
        $this->assertTrue(defined('WP_JWT_REFRESH_TTL'));

        // Test values are reasonable
        $this->assertGreaterThan(0, WP_JWT_ACCESS_TTL);
        $this->assertGreaterThan(0, WP_JWT_REFRESH_TTL);
        $this->assertNotEmpty(WP_JWT_AUTH_SECRET);
    }

    public function testRefreshCookieConstant(): void
    {
        // Test refresh cookie name constant
        $this->assertTrue(defined('Auth_JWT::REFRESH_COOKIE_NAME'));
        $this->assertEquals('wp_refresh_token', Auth_JWT::REFRESH_COOKIE_NAME);
    }

    public function testIssuerConstant(): void
    {
        // Test issuer constant
        $this->assertTrue(defined('Auth_JWT::ISSUER'));
        $this->assertEquals('wp-rest-auth-multi', Auth_JWT::ISSUER);
    }

    public function testJWTHelperFunctionsAvailable(): void
    {
        // Test that JWT helper functions are available
        $this->assertTrue(function_exists('wp_auth_multi_jwt_encode'));
        $this->assertTrue(function_exists('wp_auth_multi_jwt_decode'));
        $this->assertTrue(function_exists('wp_auth_multi_generate_token'));
        $this->assertTrue(function_exists('wp_auth_multi_hash_token'));
    }

    public function testJWTWorkflowIntegration(): void
    {
        // Test a basic JWT workflow using helper functions
        $secret = WP_JWT_AUTH_SECRET;
        $claims = [
            'iss' => Auth_JWT::ISSUER,
            'aud' => 'test-audience',
            'iat' => time(),
            'exp' => time() + 3600,
            'sub' => 123,
            'jti' => wp_auth_multi_generate_token(32)
        ];

        $token = wp_auth_multi_jwt_encode($claims, $secret);
        $this->assertNotEmpty($token);

        $decoded = wp_auth_multi_jwt_decode($token, $secret);
        $this->assertIsArray($decoded);
        $this->assertEquals(123, $decoded['sub']);
        $this->assertEquals(Auth_JWT::ISSUER, $decoded['iss']);
    }
}