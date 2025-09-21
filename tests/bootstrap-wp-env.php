<?php
/**
 * PHPUnit bootstrap file for wp-env testing environment
 */

// Define testing environment constants
if (!defined('WP_TESTS_PHPUNIT_POLYFILLS_PATH')) {
    define('WP_TESTS_PHPUNIT_POLYFILLS_PATH', dirname(__DIR__) . '/vendor/yoast/phpunit-polyfills');
}

// Load Composer autoloader
$composer_autoloader = dirname(__DIR__) . '/vendor/autoload.php';
if (file_exists($composer_autoloader)) {
    require_once $composer_autoloader;
} else {
    echo "Warning: Composer autoloader not found. Please run 'composer install'.\n";
}

// WordPress test environment paths for wp-env
$_tests_dir = getenv('WP_TESTS_DIR');
if (!$_tests_dir) {
    $_tests_dir = '/wordpress-phpunit/wp-tests';
}

// WordPress core directory for wp-env
$wp_core_dir = getenv('WP_CORE_DIR');
if (!$wp_core_dir) {
    $wp_core_dir = '/var/www/html';
}

// Give access to tests_add_filter() function
if (file_exists($_tests_dir . '/includes/functions.php')) {
    require_once $_tests_dir . '/includes/functions.php';
}

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin() {
    // Define test constants for JWT
    if (!defined('WP_JWT_AUTH_SECRET')) {
        define('WP_JWT_AUTH_SECRET', 'test-secret-key-for-testing-purposes-only-never-use-in-production-environment-this-should-be-long-and-random');
    }

    if (!defined('WP_JWT_ACCESS_TTL')) {
        define('WP_JWT_ACCESS_TTL', 3600);
    }

    if (!defined('WP_JWT_REFRESH_TTL')) {
        define('WP_JWT_REFRESH_TTL', 86400);
    }

    // Load the plugin
    require dirname(__DIR__) . '/wp-rest-auth-multi.php';
}

if (function_exists('tests_add_filter')) {
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');
}

/**
 * Set up WordPress test environment
 */
if (file_exists($_tests_dir . '/includes/bootstrap.php')) {
    require $_tests_dir . '/includes/bootstrap.php';
} else {
    // Fallback bootstrap for cases where wp-env is not fully set up
    echo "Warning: WordPress test environment not found. Some tests may not work correctly.\n";

    // Define minimal WordPress constants
    if (!defined('ABSPATH')) {
        define('ABSPATH', $wp_core_dir . '/');
    }

    if (!defined('WP_DEBUG')) {
        define('WP_DEBUG', true);
    }

    if (!defined('WP_DEBUG_LOG')) {
        define('WP_DEBUG_LOG', true);
    }

    // Load our plugin manually
    _manually_load_plugin();
}

// Load test helpers
require_once __DIR__ . '/helpers/TestCase.php';
require_once __DIR__ . '/helpers/MockFactory.php';

// Create database tables for testing if we're in a WordPress environment
if (function_exists('maybe_create_table') && defined('ABSPATH')) {
    global $wpdb;

    // Create refresh tokens table
    $table_name = $wpdb->prefix . 'auth_refresh_tokens';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id int(11) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        token varchar(255) NOT NULL,
        expires_at datetime NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY token (token),
        KEY expires_at (expires_at)
    ) $charset_collate;";

    maybe_create_table($table_name, $sql);
}

// Set up test database options
if (function_exists('update_option')) {
    // Set up default admin settings for testing
    update_option('wp_rest_auth_multi_jwt_settings', [
        'secret_key' => WP_JWT_AUTH_SECRET,
        'access_token_expiry' => WP_JWT_ACCESS_TTL,
        'refresh_token_expiry' => WP_JWT_REFRESH_TTL
    ]);

    update_option('wp_rest_auth_multi_oauth2_settings', [
        'clients' => [
            'test-client' => [
                'name' => 'Test Client',
                'redirect_uris' => [
                    'http://localhost:3000/callback',
                    'http://localhost:5173/callback',
                    'http://localhost:5174/callback',
                    'http://localhost:5175/callback'
                ],
                'created_at' => date('Y-m-d H:i:s')
            ]
        ]
    ]);

    update_option('wp_rest_auth_multi_general_settings', [
        'enable_debug_logging' => true,
        'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175"
    ]);
}

// Mock additional WordPress functions if needed
if (!function_exists('wp_create_nonce')) {
    function wp_create_nonce($action) {
        return 'test-nonce-' . md5($action . wp_salt());
    }
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce($nonce, $action) {
        return $nonce === wp_create_nonce($action);
    }
}

if (!function_exists('wp_salt')) {
    function wp_salt($scheme = 'auth') {
        return 'test-salt-' . $scheme;
    }
}

// Set up REST API testing environment
if (function_exists('rest_get_server')) {
    global $wp_rest_server;
    $wp_rest_server = rest_get_server();
}

echo "WP REST Auth Multi test environment loaded successfully!\n";
echo "WordPress version: " . (defined('WP_VERSION') ? WP_VERSION : 'Unknown') . "\n";
echo "PHP version: " . PHP_VERSION . "\n";
echo "Test directory: " . $_tests_dir . "\n";
echo "WordPress directory: " . $wp_core_dir . "\n\n";