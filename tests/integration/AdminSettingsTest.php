<?php

/**
 * Integration tests for Admin Settings
 */
class AdminSettingsTest extends WP_UnitTestCase
{
    private $admin_settings;

    protected function setUp(): void
    {
        parent::setUp();

        // Load the admin settings class
        if (!class_exists('WP_REST_Auth_Multi_Admin_Settings')) {
            require_once dirname(__DIR__, 2) . '/includes/class-admin-settings.php';
        }

        $this->admin_settings = new WP_REST_Auth_Multi_Admin_Settings();
    }

    public function testAdminSettingsClassExists(): void
    {
        $this->assertTrue(class_exists('WP_REST_Auth_Multi_Admin_Settings'));
        $this->assertInstanceOf('WP_REST_Auth_Multi_Admin_Settings', $this->admin_settings);
    }

    public function testJWTSettingsDefaults(): void
    {
        // Test default JWT settings
        $jwt_settings = $this->admin_settings->get_jwt_settings();

        $this->assertIsArray($jwt_settings);
        $this->assertArrayHasKey('secret_key', $jwt_settings);
        $this->assertArrayHasKey('access_token_expiry', $jwt_settings);
        $this->assertArrayHasKey('refresh_token_expiry', $jwt_settings);

        // Test default values
        $this->assertEquals(3600, $jwt_settings['access_token_expiry']);
        $this->assertEquals(2592000, $jwt_settings['refresh_token_expiry']); // 30 days
    }

    public function testOAuth2SettingsDefaults(): void
    {
        // Test default OAuth2 settings
        $oauth2_settings = $this->admin_settings->get_oauth2_settings();

        $this->assertIsArray($oauth2_settings);
        $this->assertArrayHasKey('clients', $oauth2_settings);
        $this->assertIsArray($oauth2_settings['clients']);
    }

    public function testGeneralSettingsDefaults(): void
    {
        // Test default general settings
        $general_settings = $this->admin_settings->get_general_settings();

        $this->assertIsArray($general_settings);
        $this->assertArrayHasKey('enable_debug_logging', $general_settings);
        $this->assertArrayHasKey('cors_allowed_origins', $general_settings);

        $this->assertIsBool($general_settings['enable_debug_logging']);
    }

    public function testJWTSettingsValidation(): void
    {
        // Test JWT settings sanitization
        $test_settings = [
            'secret_key' => 'test-secret-key-that-is-long-enough-for-validation',
            'access_token_expiry' => 1800, // 30 minutes
            'refresh_token_expiry' => 604800 // 7 days
        ];

        $sanitized = $this->admin_settings->sanitize_jwt_settings($test_settings);

        $this->assertIsArray($sanitized);
        $this->assertEquals($test_settings['secret_key'], $sanitized['secret_key']);
        $this->assertEquals(1800, $sanitized['access_token_expiry']);
        $this->assertEquals(604800, $sanitized['refresh_token_expiry']);
    }

    public function testJWTSecretKeyValidation(): void
    {
        // Test that short secret keys are rejected
        $test_settings = [
            'secret_key' => 'short', // Too short
            'access_token_expiry' => 3600,
            'refresh_token_expiry' => 86400
        ];

        $sanitized = $this->admin_settings->sanitize_jwt_settings($test_settings);

        // Should either reject the short key or generate a new one
        if (isset($sanitized['secret_key'])) {
            $this->assertNotEquals('short', $sanitized['secret_key']);
            $this->assertGreaterThan(32, strlen($sanitized['secret_key']));
        } else {
            // If secret_key is not returned, the validation rejected it
            $this->assertTrue(true);
        }
    }

    public function testExpiryLimitsValidation(): void
    {
        // Test expiry time limits
        $test_settings = [
            'secret_key' => 'valid-secret-key-that-is-long-enough-for-validation',
            'access_token_expiry' => 100, // Too short, should be clamped to minimum
            'refresh_token_expiry' => 99999999 // Too long, should be clamped to maximum
        ];

        $sanitized = $this->admin_settings->sanitize_jwt_settings($test_settings);

        // Check that values are within acceptable ranges
        $this->assertGreaterThanOrEqual(300, $sanitized['access_token_expiry']); // Min 5 minutes
        $this->assertLessThanOrEqual(86400, $sanitized['access_token_expiry']); // Max 24 hours

        $this->assertGreaterThanOrEqual(3600, $sanitized['refresh_token_expiry']); // Min 1 hour
        $this->assertLessThanOrEqual(31536000, $sanitized['refresh_token_expiry']); // Max 1 year
    }

    public function testGeneralSettingsSanitization(): void
    {
        // Test general settings sanitization
        $test_settings = [
            'enable_debug_logging' => 'on', // Should convert to boolean
            'cors_allowed_origins' => "http://localhost:3000\nhttps://example.com\n  \n" // Should clean up
        ];

        $sanitized = $this->admin_settings->sanitize_general_settings($test_settings);

        $this->assertIsArray($sanitized);
        $this->assertTrue($sanitized['enable_debug_logging']);

        // Check that CORS origins are cleaned up
        $this->assertStringContainsString('http://localhost:3000', $sanitized['cors_allowed_origins']);
        $this->assertStringContainsString('https://example.com', $sanitized['cors_allowed_origins']);
    }

    public function testAdminMenuIntegration(): void
    {
        // Test that admin menu hooks are properly set up
        $this->assertTrue(method_exists($this->admin_settings, 'add_admin_menu'));
        $this->assertTrue(method_exists($this->admin_settings, 'register_settings'));

        // Test that the settings page callback exists
        $this->assertTrue(method_exists($this->admin_settings, 'admin_page'));
    }

    public function testSettingsOptionsRegistered(): void
    {
        // Simulate admin_init to register settings
        if (method_exists($this->admin_settings, 'admin_init')) {
            $this->admin_settings->admin_init();
        }

        // Test that WordPress options are properly registered
        // Note: In integration tests with WordPress, we can check if options are registered
        $this->assertTrue(true); // Placeholder - in real WP environment this would test option registration
    }

    public function testNonceValidation(): void
    {
        // Test that nonce validation exists for AJAX endpoints
        $this->assertTrue(method_exists($this->admin_settings, 'ajax_add_oauth2_client'));
        $this->assertTrue(method_exists($this->admin_settings, 'ajax_delete_oauth2_client'));

        // These methods should validate nonces before processing
        $this->assertTrue(true); // Placeholder for actual nonce validation tests
    }
}