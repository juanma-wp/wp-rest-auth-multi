<?php
/**
 * Plugin Name: WP REST Multi Auth (JWT + OAuth2)
 * Description: Provides JWT with refresh tokens (HttpOnly cookies) and OAuth2 authentication for WordPress REST API
 * Version: 1.0.0
 * Author: WordPress Developer
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: GPL v2 or later
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WP_REST_AUTH_MULTI_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WP_REST_AUTH_MULTI_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WP_REST_AUTH_MULTI_VERSION', '1.0.0');

class WP_REST_Auth_Multi {

    private $auth_jwt;
    private $auth_oauth2;
    private $admin_settings;
    private $api_proxy;

    public function __construct() {
        add_action('plugins_loaded', [$this, 'init']);
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    public function init() {
        $this->load_dependencies();
        $this->setup_constants();
        $this->init_hooks();
    }

    private function load_dependencies() {
        require_once WP_REST_AUTH_MULTI_PLUGIN_DIR . 'includes/helpers.php';
        require_once WP_REST_AUTH_MULTI_PLUGIN_DIR . 'includes/class-admin-settings.php';
        require_once WP_REST_AUTH_MULTI_PLUGIN_DIR . 'includes/class-auth-jwt.php';
        require_once WP_REST_AUTH_MULTI_PLUGIN_DIR . 'includes/class-auth-oauth2.php';
        require_once WP_REST_AUTH_MULTI_PLUGIN_DIR . 'includes/class-api-proxy.php';

        // Initialize admin settings
        if (is_admin()) {
            $this->admin_settings = new WP_REST_Auth_Multi_Admin_Settings();
        }

        $this->auth_jwt = new Auth_JWT();
        $this->auth_oauth2 = new Auth_OAuth2();
        $this->api_proxy = new WP_REST_API_Proxy();
    }

    private function setup_constants() {
        $jwt_settings = WP_REST_Auth_Multi_Admin_Settings::get_jwt_settings();

        // Setup JWT constants from admin settings or fallback to wp-config.php
        if (!defined('WP_JWT_AUTH_SECRET')) {
            $secret = $jwt_settings['secret_key'] ?? '';
            if (!empty($secret)) {
                define('WP_JWT_AUTH_SECRET', $secret);
            } else {
                // Check if it's defined in wp-config.php as fallback
                if (!defined('WP_JWT_AUTH_SECRET')) {
                    add_action('admin_notices', [$this, 'missing_config_notice']);
                    return;
                }
            }
        }

        // Set token expiration times from admin settings
        if (!defined('WP_JWT_ACCESS_TTL')) {
            define('WP_JWT_ACCESS_TTL', $jwt_settings['access_token_expiry'] ?? 3600);
        }

        if (!defined('WP_JWT_REFRESH_TTL')) {
            define('WP_JWT_REFRESH_TTL', $jwt_settings['refresh_token_expiry'] ?? 2592000);
        }
    }

    private function init_hooks() {
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_filter('rest_authentication_errors', [$this, 'maybe_auth_bearer'], 20);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
    }

    public function register_rest_routes() {
        $this->auth_jwt->register_routes();
        $this->auth_oauth2->register_routes();
    }

    public function maybe_auth_bearer($result) {
        if (!empty($result)) {
            return $result;
        }

        $auth_header = $this->get_auth_header();
        if (!$auth_header || stripos($auth_header, 'Bearer ') !== 0) {
            return $result;
        }

        $token = trim(substr($auth_header, 7));

        // Try JWT authentication first
        $jwt_result = $this->auth_jwt->authenticate_bearer($token);
        if (!is_wp_error($jwt_result)) {
            return $jwt_result;
        }

        // Try OAuth2 authentication
        $oauth_result = $this->auth_oauth2->authenticate_bearer($token);
        if (!is_wp_error($oauth_result)) {
            return $oauth_result;
        }

        // Return the JWT error as it's more descriptive
        return $jwt_result;
    }

    private function get_auth_header() {
        $auth_header = '';

        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_SERVER['Authorization'])) {
            $auth_header = $_SERVER['Authorization'];
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = $headers['Authorization'] ?? '';
        }

        return $auth_header;
    }

    public function activate() {
        $this->create_refresh_tokens_table();
        $this->create_oauth_clients();
    }

    public function deactivate() {
        // Clean up refresh tokens on deactivation
        global $wpdb;
        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $wpdb->query("DELETE FROM {$table_name} WHERE expires_at < " . time());
    }

    private function create_refresh_tokens_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            token_hash varchar(255) NOT NULL,
            expires_at bigint(20) NOT NULL,
            revoked_at bigint(20) DEFAULT NULL,
            issued_at bigint(20) NOT NULL,
            user_agent varchar(500) DEFAULT NULL,
            ip_address varchar(45) DEFAULT NULL,
            created_at bigint(20) DEFAULT NULL,
            is_revoked tinyint(1) DEFAULT 0,
            client_id varchar(255) DEFAULT NULL,
            scopes text DEFAULT NULL,
            token_type varchar(50) DEFAULT 'jwt',
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY token_hash (token_hash),
            KEY expires_at (expires_at),
            KEY token_type (token_type)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    private function create_oauth_clients() {
        $clients = get_option('oauth2_clients', []);

        // Always update the demo client to ensure correct redirect URIs
        $clients['demo-client'] = [
            'client_secret' => wp_hash_password('demo-secret'),
            'redirect_uris' => [
                'http://localhost:3000/callback',
                'http://localhost:5173/callback',
                'http://localhost:5174/callback',
                'http://localhost:5175/callback',
                'https://example.com/callback'
            ]
        ];

        update_option('oauth2_clients', $clients);
    }

    public function missing_config_notice() {
        $settings_url = admin_url('options-general.php?page=wp-rest-auth-multi');
        echo '<div class="notice notice-error"><p>';
        echo '<strong>WP REST Multi Auth:</strong> JWT Secret Key is required for the plugin to work. ';
        echo '<a href="' . esc_url($settings_url) . '">Configure it in the plugin settings</a> ';
        echo 'or define <code>WP_JWT_AUTH_SECRET</code> in your wp-config.php file.';
        echo '</p></div>';
    }

    public function enqueue_scripts() {
        if (is_admin()) {
            wp_enqueue_script(
                'wp-rest-auth-multi-admin',
                WP_REST_AUTH_MULTI_PLUGIN_URL . 'assets/admin.js',
                ['jquery'],
                WP_REST_AUTH_MULTI_VERSION,
                true
            );

            wp_localize_script('wp-rest-auth-multi-admin', 'wpRestAuthMulti', [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('wp_rest_auth_multi_nonce'),
                'restUrl' => rest_url()
            ]);
        }
    }
}

new WP_REST_Auth_Multi();