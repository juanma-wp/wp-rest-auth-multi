<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_REST_Auth_Multi_Admin_Settings {

    const OPTION_GROUP = 'wp_rest_auth_multi_settings';
    const OPTION_JWT_SETTINGS = 'wp_rest_auth_multi_jwt_settings';
    const OPTION_OAUTH2_SETTINGS = 'wp_rest_auth_multi_oauth2_settings';
    const OPTION_GENERAL_SETTINGS = 'wp_rest_auth_multi_general_settings';

    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);

        // AJAX handlers for OAuth2 client management
        add_action('wp_ajax_add_oauth2_client', [$this, 'ajax_add_oauth2_client']);
        add_action('wp_ajax_delete_oauth2_client', [$this, 'ajax_delete_oauth2_client']);
    }

    public function add_admin_menu() {
        add_options_page(
            'WP REST Auth Multi Settings',
            'WP REST Auth Multi',
            'manage_options',
            'wp-rest-auth-multi',
            [$this, 'admin_page']
        );
    }

    public function register_settings() {
        // Register setting groups
        register_setting(self::OPTION_GROUP, self::OPTION_JWT_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_jwt_settings']
        ]);

        register_setting(self::OPTION_GROUP, self::OPTION_OAUTH2_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_oauth2_settings']
        ]);

        register_setting(self::OPTION_GROUP, self::OPTION_GENERAL_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_general_settings']
        ]);

        // JWT Settings Section
        add_settings_section(
            'jwt_settings',
            'JWT Authentication Settings',
            [$this, 'jwt_settings_section'],
            'wp-rest-auth-multi-jwt'
        );

        add_settings_field(
            'jwt_secret_key',
            'JWT Secret Key',
            [$this, 'jwt_secret_key_field'],
            'wp-rest-auth-multi-jwt',
            'jwt_settings'
        );

        add_settings_field(
            'jwt_access_token_expiry',
            'Access Token Expiry (seconds)',
            [$this, 'jwt_access_token_expiry_field'],
            'wp-rest-auth-multi-jwt',
            'jwt_settings'
        );

        add_settings_field(
            'jwt_refresh_token_expiry',
            'Refresh Token Expiry (seconds)',
            [$this, 'jwt_refresh_token_expiry_field'],
            'wp-rest-auth-multi-jwt',
            'jwt_settings'
        );

        // OAuth2 Settings Section
        add_settings_section(
            'oauth2_settings',
            'OAuth2 Settings',
            [$this, 'oauth2_settings_section'],
            'wp-rest-auth-multi-oauth2'
        );

        // General Settings Section
        add_settings_section(
            'general_settings',
            'General Settings',
            [$this, 'general_settings_section'],
            'wp-rest-auth-multi-general'
        );

        add_settings_field(
            'enable_debug_logging',
            'Enable Debug Logging',
            [$this, 'enable_debug_logging_field'],
            'wp-rest-auth-multi-general',
            'general_settings'
        );

        add_settings_field(
            'cors_allowed_origins',
            'CORS Allowed Origins',
            [$this, 'cors_allowed_origins_field'],
            'wp-rest-auth-multi-general',
            'general_settings'
        );
    }

    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_wp-rest-auth-multi') {
            return;
        }

        wp_enqueue_script(
            'wp-rest-auth-multi-admin',
            plugin_dir_url(dirname(__FILE__)) . 'assets/admin.js',
            ['jquery'],
            '1.0.0',
            true
        );

        wp_localize_script('wp-rest-auth-multi-admin', 'wpRestAuthMulti', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_rest_auth_multi_nonce')
        ]);

        wp_enqueue_style(
            'wp-rest-auth-multi-admin',
            plugin_dir_url(dirname(__FILE__)) . 'assets/admin.css',
            [],
            '1.0.0'
        );
    }

    public function admin_page() {
        if (isset($_GET['tab'])) {
            $active_tab = sanitize_text_field($_GET['tab']);
        } else {
            $active_tab = 'jwt';
        }
        ?>
        <div class="wrap">
            <h1>WP REST Auth Multi Settings</h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=wp-rest-auth-multi&tab=jwt" class="nav-tab <?php echo $active_tab == 'jwt' ? 'nav-tab-active' : ''; ?>">JWT Settings</a>
                <a href="?page=wp-rest-auth-multi&tab=oauth2" class="nav-tab <?php echo $active_tab == 'oauth2' ? 'nav-tab-active' : ''; ?>">OAuth2 Settings</a>
                <a href="?page=wp-rest-auth-multi&tab=general" class="nav-tab <?php echo $active_tab == 'general' ? 'nav-tab-active' : ''; ?>">General Settings</a>
                <a href="?page=wp-rest-auth-multi&tab=help" class="nav-tab <?php echo $active_tab == 'help' ? 'nav-tab-active' : ''; ?>">Help & Documentation</a>
            </nav>

            <form method="post" action="options.php">
                <?php
                settings_fields(self::OPTION_GROUP);

                if ($active_tab == 'jwt') {
                    do_settings_sections('wp-rest-auth-multi-jwt');
                    submit_button();
                } elseif ($active_tab == 'oauth2') {
                    $this->render_oauth2_tab();
                } elseif ($active_tab == 'general') {
                    do_settings_sections('wp-rest-auth-multi-general');
                    submit_button();
                } elseif ($active_tab == 'help') {
                    $this->render_help_tab();
                }
                ?>
            </form>
        </div>
        <?php
    }

    private function render_oauth2_tab() {
        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];
        ?>
        <div class="oauth2-settings">
            <h2>OAuth2 Client Management</h2>
            <p>Add OAuth2 clients that can authenticate with your WordPress site. Each client needs a unique Client ID and allowed redirect URIs.</p>

            <div class="oauth2-add-client">
                <h3>Add New OAuth2 Client</h3>
                <table class="form-table">
                    <tr>
                        <th><label for="new_client_name">Client Name</label></th>
                        <td><input type="text" id="new_client_name" class="regular-text" placeholder="My React App" /></td>
                    </tr>
                    <tr>
                        <th><label for="new_client_id">Client ID</label></th>
                        <td>
                            <input type="text" id="new_client_id" class="regular-text" placeholder="my-react-app" />
                            <button type="button" id="generate_client_id" class="button">Generate Random</button>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="new_client_redirect_uris">Redirect URIs</label></th>
                        <td>
                            <textarea id="new_client_redirect_uris" class="large-text" rows="3" placeholder="http://localhost:3000/callback&#10;http://localhost:5173/callback&#10;https://myapp.com/callback"></textarea>
                            <p class="description">One redirect URI per line. These must match exactly what your application sends.</p>
                        </td>
                    </tr>
                </table>
                <button type="button" id="add_oauth2_client" class="button button-primary">Add OAuth2 Client</button>
            </div>

            <div class="oauth2-existing-clients">
                <h3>Existing OAuth2 Clients</h3>
                <?php if (empty($clients)): ?>
                    <p>No OAuth2 clients configured yet.</p>
                <?php else: ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th>Client Name</th>
                                <th>Client ID</th>
                                <th>Redirect URIs</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($clients as $client_id => $client): ?>
                                <tr>
                                    <td><?php echo esc_html($client['name'] ?? 'Unnamed Client'); ?></td>
                                    <td><code><?php echo esc_html($client_id); ?></code></td>
                                    <td>
                                        <?php
                                        $uris = $client['redirect_uris'] ?? [];
                                        foreach ($uris as $uri) {
                                            echo '<code>' . esc_html($uri) . '</code><br>';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <button type="button" class="button delete-client" data-client-id="<?php echo esc_attr($client_id); ?>">Delete</button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    private function render_help_tab() {
        ?>
        <div class="help-tab">
            <h2>Help & Documentation</h2>

            <div class="help-section">
                <h3>🔐 JWT Authentication</h3>
                <p><strong>JWT Secret Key:</strong> A secure random string used to sign JWT tokens. Keep this secret and never share it.</p>
                <p><strong>Access Token Expiry:</strong> How long access tokens remain valid (default: 3600 seconds / 1 hour).</p>
                <p><strong>Refresh Token Expiry:</strong> How long refresh tokens remain valid (default: 2592000 seconds / 30 days).</p>

                <h4>JWT Endpoints:</h4>
                <ul>
                    <li><code>POST /wp-json/wp-rest-auth-multi/v1/jwt/login</code> - Login with username/password</li>
                    <li><code>POST /wp-json/wp-rest-auth-multi/v1/jwt/refresh</code> - Refresh access token</li>
                    <li><code>POST /wp-json/wp-rest-auth-multi/v1/jwt/validate</code> - Validate JWT token</li>
                </ul>
            </div>

            <div class="help-section">
                <h3>🔑 OAuth2 Authentication</h3>
                <p><strong>Client ID:</strong> Unique identifier for your application.</p>
                <p><strong>Redirect URIs:</strong> Allowed URLs where users will be redirected after authorization.</p>

                <h4>OAuth2 Flow:</h4>
                <ol>
                    <li>Redirect user to: <code>/wp-json/wp-rest-auth-multi/v1/oauth2/authorize</code></li>
                    <li>User grants permission</li>
                    <li>Exchange authorization code for tokens at: <code>/wp-json/wp-rest-auth-multi/v1/oauth2/token</code></li>
                    <li>Use access token to make authenticated requests</li>
                </ol>

                <h4>Available OAuth2 Scopes:</h4>
                <ul>
                    <li><code>read</code> - View posts, pages, and profile information</li>
                    <li><code>write</code> - Create and edit posts and pages</li>
                    <li><code>delete</code> - Delete posts and pages</li>
                    <li><code>upload_files</code> - Upload and manage media files</li>
                    <li><code>moderate_comments</code> - Moderate and manage comments</li>
                    <li><code>manage_categories</code> - Create and manage categories and tags</li>
                </ul>
            </div>

            <div class="help-section">
                <h3>⚙️ General Settings</h3>
                <p><strong>Debug Logging:</strong> Enable detailed logging for troubleshooting authentication issues.</p>
                <p><strong>CORS Allowed Origins:</strong> Domains allowed to make cross-origin requests to your WordPress REST API.</p>
            </div>

            <div class="help-section">
                <h3>🔧 Troubleshooting</h3>
                <h4>Common Issues:</h4>
                <ul>
                    <li><strong>Invalid JWT Token:</strong> Check that your JWT secret key is properly configured</li>
                    <li><strong>OAuth2 Redirect URI Mismatch:</strong> Ensure redirect URIs match exactly (including protocol and port)</li>
                    <li><strong>CORS Errors:</strong> Add your frontend domain to the CORS allowed origins</li>
                    <li><strong>Token Expired:</strong> Implement proper token refresh logic in your application</li>
                </ul>

                <h4>Debug Information:</h4>
                <p><strong>Plugin Version:</strong> <?php echo esc_html(get_option('wp_rest_auth_multi_version', '1.0.0')); ?></p>
                <p><strong>WordPress Version:</strong> <?php echo esc_html(get_bloginfo('version')); ?></p>
                <p><strong>PHP Version:</strong> <?php echo esc_html(PHP_VERSION); ?></p>
            </div>
        </div>
        <?php
    }

    // Section callbacks
    public function jwt_settings_section() {
        echo '<p>Configure JWT authentication settings. JWT tokens are used for stateless authentication with your WordPress REST API.</p>';
    }

    public function oauth2_settings_section() {
        echo '<p>Configure OAuth2 clients and settings. OAuth2 provides secure authorization for third-party applications.</p>';
    }

    public function general_settings_section() {
        echo '<p>General plugin settings and security options.</p>';
    }

    // Field callbacks
    public function jwt_secret_key_field() {
        $settings = get_option(self::OPTION_JWT_SETTINGS, []);
        $value = $settings['secret_key'] ?? '';
        ?>
        <input type="password" id="jwt_secret_key" name="<?php echo self::OPTION_JWT_SETTINGS; ?>[secret_key]" value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <button type="button" id="generate_jwt_secret" class="button">Generate New Secret</button>
        <button type="button" id="toggle_jwt_secret" class="button">Show/Hide</button>
        <p class="description">A secure random string used to sign JWT tokens. Generate a new one or enter your own (minimum 32 characters recommended).</p>
        <?php
    }

    public function jwt_access_token_expiry_field() {
        $settings = get_option(self::OPTION_JWT_SETTINGS, []);
        $value = $settings['access_token_expiry'] ?? 3600;
        ?>
        <input type="number" id="jwt_access_token_expiry" name="<?php echo self::OPTION_JWT_SETTINGS; ?>[access_token_expiry]" value="<?php echo esc_attr($value); ?>" min="300" max="86400" />
        <p class="description">How long access tokens remain valid in seconds. Default: 3600 (1 hour). Range: 300-86400 seconds.</p>
        <?php
    }

    public function jwt_refresh_token_expiry_field() {
        $settings = get_option(self::OPTION_JWT_SETTINGS, []);
        $value = $settings['refresh_token_expiry'] ?? 2592000;
        ?>
        <input type="number" id="jwt_refresh_token_expiry" name="<?php echo self::OPTION_JWT_SETTINGS; ?>[refresh_token_expiry]" value="<?php echo esc_attr($value); ?>" min="3600" max="31536000" />
        <p class="description">How long refresh tokens remain valid in seconds. Default: 2592000 (30 days). Range: 3600-31536000 seconds.</p>
        <?php
    }

    public function enable_debug_logging_field() {
        $settings = get_option(self::OPTION_GENERAL_SETTINGS, []);
        $checked = isset($settings['enable_debug_logging']) && $settings['enable_debug_logging'];
        ?>
        <label>
            <input type="checkbox" name="<?php echo self::OPTION_GENERAL_SETTINGS; ?>[enable_debug_logging]" value="1" <?php checked($checked); ?> />
            Enable detailed logging for authentication events
        </label>
        <p class="description">Logs will be written to your WordPress debug log. Ensure WP_DEBUG_LOG is enabled.</p>
        <?php
    }

    public function cors_allowed_origins_field() {
        $settings = get_option(self::OPTION_GENERAL_SETTINGS, []);
        $value = $settings['cors_allowed_origins'] ?? "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175";
        ?>
        <textarea name="<?php echo self::OPTION_GENERAL_SETTINGS; ?>[cors_allowed_origins]" class="large-text" rows="5"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">One origin per line. Use * to allow all origins (not recommended for production).</p>
        <?php
    }

    // Sanitization callbacks
    public function sanitize_jwt_settings($input) {
        $sanitized = [];

        if (isset($input['secret_key'])) {
            $secret_key = sanitize_text_field($input['secret_key']);
            if (strlen($secret_key) < 32) {
                add_settings_error(self::OPTION_JWT_SETTINGS, 'jwt_secret_key', 'JWT Secret Key must be at least 32 characters long.');
            } else {
                $sanitized['secret_key'] = $secret_key;
            }
        }

        if (isset($input['access_token_expiry'])) {
            $expiry = intval($input['access_token_expiry']);
            $sanitized['access_token_expiry'] = max(300, min(86400, $expiry));
        }

        if (isset($input['refresh_token_expiry'])) {
            $expiry = intval($input['refresh_token_expiry']);
            $sanitized['refresh_token_expiry'] = max(3600, min(31536000, $expiry));
        }

        return $sanitized;
    }

    public function sanitize_oauth2_settings($input) {
        return $input; // OAuth2 settings are managed via AJAX
    }

    public function sanitize_general_settings($input) {
        $sanitized = [];

        $sanitized['enable_debug_logging'] = isset($input['enable_debug_logging']) && $input['enable_debug_logging'];

        if (isset($input['cors_allowed_origins'])) {
            $origins = sanitize_textarea_field($input['cors_allowed_origins']);
            $sanitized['cors_allowed_origins'] = $origins;
        }

        return $sanitized;
    }

    // AJAX handlers
    public function ajax_add_oauth2_client() {
        if (!wp_verify_nonce($_POST['nonce'], 'wp_rest_auth_multi_nonce')) {
            wp_die('Invalid nonce');
        }

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $name = sanitize_text_field($_POST['name']);
        $client_id = sanitize_text_field($_POST['client_id']);
        $redirect_uris = array_map('esc_url_raw', array_filter(array_map('trim', explode("\n", $_POST['redirect_uris']))));

        if (empty($name) || empty($client_id) || empty($redirect_uris)) {
            wp_send_json_error('All fields are required.');
        }

        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];

        if (isset($clients[$client_id])) {
            wp_send_json_error('Client ID already exists.');
        }

        $clients[$client_id] = [
            'name' => $name,
            'redirect_uris' => $redirect_uris,
            'created_at' => current_time('mysql')
        ];

        $oauth2_settings['clients'] = $clients;
        update_option(self::OPTION_OAUTH2_SETTINGS, $oauth2_settings);

        wp_send_json_success('OAuth2 client added successfully.');
    }

    public function ajax_delete_oauth2_client() {
        if (!wp_verify_nonce($_POST['nonce'], 'wp_rest_auth_multi_nonce')) {
            wp_die('Invalid nonce');
        }

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $client_id = sanitize_text_field($_POST['client_id']);

        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];

        if (!isset($clients[$client_id])) {
            wp_send_json_error('Client not found.');
        }

        unset($clients[$client_id]);
        $oauth2_settings['clients'] = $clients;
        update_option(self::OPTION_OAUTH2_SETTINGS, $oauth2_settings);

        wp_send_json_success('OAuth2 client deleted successfully.');
    }

    // Helper method to get settings
    public static function get_jwt_settings() {
        return get_option(self::OPTION_JWT_SETTINGS, [
            'secret_key' => '',
            'access_token_expiry' => 3600,
            'refresh_token_expiry' => 2592000
        ]);
    }

    public static function get_oauth2_settings() {
        return get_option(self::OPTION_OAUTH2_SETTINGS, [
            'clients' => []
        ]);
    }

    public static function get_general_settings() {
        return get_option(self::OPTION_GENERAL_SETTINGS, [
            'enable_debug_logging' => false,
            'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175"
        ]);
    }
}