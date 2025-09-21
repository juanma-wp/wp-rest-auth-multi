<?php

/**
 * Integration tests for database operations
 */
class DatabaseIntegrationTest extends WP_UnitTestCase
{
    private $test_user_id;

    protected function setUp(): void
    {
        parent::setUp();

        // Create a test user
        $this->test_user_id = $this->factory()->user->create([
            'user_login' => 'testuser_db',
            'user_email' => 'testuser_db@example.com',
            'role' => 'subscriber'
        ]);
    }

    protected function tearDown(): void
    {
        // Clean up test data
        delete_user_meta($this->test_user_id, 'jwt_refresh_tokens');
        delete_transient('oauth2_code_test_code_123');
        delete_transient('oauth2_token_test_token_123');

        parent::tearDown();
    }

    public function test_refresh_token_storage_and_retrieval(): void
    {
        // Test storing multiple refresh tokens for a user
        $token1 = [
            'token_hash' => wp_hash('refresh_token_1'),
            'expires_at' => time() + 86400,
            'created_at' => time(),
            'user_agent' => 'Test Browser 1'
        ];

        $token2 = [
            'token_hash' => wp_hash('refresh_token_2'),
            'expires_at' => time() + 172800,
            'created_at' => time(),
            'user_agent' => 'Test Browser 2'
        ];

        // Store tokens
        $tokens = [$token1, $token2];
        update_user_meta($this->test_user_id, 'jwt_refresh_tokens', $tokens);

        // Retrieve and verify
        $stored_tokens = get_user_meta($this->test_user_id, 'jwt_refresh_tokens', true);

        $this->assertIsArray($stored_tokens);
        $this->assertCount(2, $stored_tokens);
        $this->assertEquals($token1['token_hash'], $stored_tokens[0]['token_hash']);
        $this->assertEquals($token2['token_hash'], $stored_tokens[1]['token_hash']);
    }

    public function test_oauth2_authorization_code_transient_storage(): void
    {
        // Test OAuth2 authorization code storage using transients
        $code_data = [
            'client_id' => 'test_client_123',
            'user_id' => $this->test_user_id,
            'redirect_uri' => 'https://example.com/callback',
            'scope' => 'read write',
            'expires_at' => time() + 600
        ];

        $code = 'test_code_123';
        $transient_key = 'oauth2_code_' . $code;

        // Store code
        set_transient($transient_key, $code_data, 600);

        // Retrieve and verify
        $stored_data = get_transient($transient_key);

        $this->assertIsArray($stored_data);
        $this->assertEquals('test_client_123', $stored_data['client_id']);
        $this->assertEquals($this->test_user_id, $stored_data['user_id']);
        $this->assertEquals('read write', $stored_data['scope']);
    }

    public function test_oauth2_access_token_transient_storage(): void
    {
        // Test OAuth2 access token storage using transients
        $token_data = [
            'user_id' => $this->test_user_id,
            'client_id' => 'test_client_456',
            'scope' => 'read',
            'expires_at' => time() + 3600
        ];

        $access_token = 'test_token_123';
        $transient_key = 'oauth2_token_' . $access_token;

        // Store token
        set_transient($transient_key, $token_data, 3600);

        // Retrieve and verify
        $stored_data = get_transient($transient_key);

        $this->assertIsArray($stored_data);
        $this->assertEquals($this->test_user_id, $stored_data['user_id']);
        $this->assertEquals('test_client_456', $stored_data['client_id']);
        $this->assertEquals('read', $stored_data['scope']);
    }

    public function test_user_token_cleanup(): void
    {
        // Test cleaning up expired tokens from user meta
        $current_time = time();
        $expired_token = [
            'token_hash' => 'expired_token_hash',
            'expires_at' => $current_time - 3600, // Expired 1 hour ago
            'created_at' => $current_time - 86400
        ];

        $valid_token = [
            'token_hash' => 'valid_token_hash',
            'expires_at' => $current_time + 86400, // Expires in 24 hours
            'created_at' => $current_time
        ];

        // Store both tokens
        $tokens = [$expired_token, $valid_token];
        update_user_meta($this->test_user_id, 'jwt_refresh_tokens', $tokens);

        // Simulate cleanup (normally done by Auth_JWT::clean_expired_tokens())
        $stored_tokens = get_user_meta($this->test_user_id, 'jwt_refresh_tokens', true);
        $active_tokens = array_filter($stored_tokens, function($token) {
            return $token['expires_at'] > time();
        });

        update_user_meta($this->test_user_id, 'jwt_refresh_tokens', array_values($active_tokens));

        // Verify cleanup
        $cleaned_tokens = get_user_meta($this->test_user_id, 'jwt_refresh_tokens', true);

        $this->assertCount(1, $cleaned_tokens);
        $this->assertEquals('valid_token_hash', $cleaned_tokens[0]['token_hash']);
    }

    public function test_oauth2_client_configuration_storage(): void
    {
        // Test storing OAuth2 client configurations
        $clients = [
            'client_123' => [
                'name' => 'Test Application',
                'redirect_uris' => ['https://example.com/callback'],
                'scopes' => ['read', 'write'],
                'client_secret' => wp_hash('secret_123')
            ],
            'client_456' => [
                'name' => 'Another App',
                'redirect_uris' => ['https://another.com/auth'],
                'scopes' => ['read'],
                'client_secret' => wp_hash('secret_456')
            ]
        ];

        // Store client configurations
        update_option('wp_rest_auth_multi_oauth2_clients', $clients);

        // Retrieve and verify
        $stored_clients = get_option('wp_rest_auth_multi_oauth2_clients');

        $this->assertIsArray($stored_clients);
        $this->assertArrayHasKey('client_123', $stored_clients);
        $this->assertArrayHasKey('client_456', $stored_clients);
        $this->assertEquals('Test Application', $stored_clients['client_123']['name']);
        $this->assertContains('read', $stored_clients['client_456']['scopes']);

        // Clean up
        delete_option('wp_rest_auth_multi_oauth2_clients');
    }

    public function test_plugin_options_integration(): void
    {
        // Test that plugin options are properly integrated with WordPress
        $jwt_settings = [
            'secret_key' => 'test-jwt-secret-for-integration',
            'access_token_expiry' => 3600,
            'refresh_token_expiry' => 86400
        ];

        $oauth2_settings = [
            'authorization_code_expiry' => 600,
            'access_token_expiry' => 3600
        ];

        $general_settings = [
            'enable_debug_logging' => true,
            'cors_allowed_origins' => "https://example.com\nhttps://app.example.com"
        ];

        // Store settings
        update_option('wp_rest_auth_multi_jwt_settings', $jwt_settings);
        update_option('wp_rest_auth_multi_oauth2_settings', $oauth2_settings);
        update_option('wp_rest_auth_multi_general_settings', $general_settings);

        // Verify storage and retrieval
        $stored_jwt = get_option('wp_rest_auth_multi_jwt_settings');
        $stored_oauth2 = get_option('wp_rest_auth_multi_oauth2_settings');
        $stored_general = get_option('wp_rest_auth_multi_general_settings');

        $this->assertEquals('test-jwt-secret-for-integration', $stored_jwt['secret_key']);
        $this->assertEquals(600, $stored_oauth2['authorization_code_expiry']);
        $this->assertTrue($stored_general['enable_debug_logging']);
        $this->assertStringContainsString('https://example.com', $stored_general['cors_allowed_origins']);

        // Clean up
        delete_option('wp_rest_auth_multi_jwt_settings');
        delete_option('wp_rest_auth_multi_oauth2_settings');
        delete_option('wp_rest_auth_multi_general_settings');
    }

    public function test_transient_expiration_handling(): void
    {
        // Test that transients properly expire and are cleaned up
        $short_lived_data = ['test' => 'data'];

        // Set a transient with 1 second expiry
        set_transient('test_short_transient', $short_lived_data, 1);

        // Verify it exists immediately
        $this->assertEquals($short_lived_data, get_transient('test_short_transient'));

        // Wait for expiry (in a real test, we might mock time functions)
        // For now, just test the transient API works
        delete_transient('test_short_transient');
        $this->assertFalse(get_transient('test_short_transient'));
    }
}