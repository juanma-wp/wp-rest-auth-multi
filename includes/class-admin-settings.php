<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_REST_Auth_Multi_Admin_Settings {

    const OPTION_GROUP = 'wp_rest_auth_multi_settings';
    const OPTION_JWT_SETTINGS = 'wp_rest_auth_multi_jwt_settings';
    const OPTION_OAUTH2_SETTINGS = 'wp_rest_auth_multi_oauth2_settings';
    const OPTION_GENERAL_SETTINGS = 'wp_rest_auth_multi_general_settings';
    const OPTION_PROXY_SETTINGS = 'wp_rest_auth_multi_proxy_settings';

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

        register_setting(self::OPTION_GROUP, self::OPTION_PROXY_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_proxy_settings']
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

        // Proxy Settings Section
        add_settings_section(
            'proxy_settings',
            'API Proxy Settings',
            [$this, 'proxy_settings_section'],
            'wp-rest-auth-multi-proxy'
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

        // Proxy Settings Fields
        add_settings_field(
            'proxy_enable',
            'Enable API Proxy',
            [$this, 'proxy_enable_field'],
            'wp-rest-auth-multi-proxy',
            'proxy_settings'
        );

        add_settings_field(
            'proxy_mode',
            'Proxy Mode',
            [$this, 'proxy_mode_field'],
            'wp-rest-auth-multi-proxy',
            'proxy_settings'
        );

        add_settings_field(
            'proxy_endpoints',
            'Proxy Endpoints',
            [$this, 'proxy_endpoints_field'],
            'wp-rest-auth-multi-proxy',
            'proxy_settings'
        );

        add_settings_field(
            'proxy_session_duration',
            'Session Duration (seconds)',
            [$this, 'proxy_session_duration_field'],
            'wp-rest-auth-multi-proxy',
            'proxy_settings'
        );

        add_settings_field(
            'proxy_allowed_domains',
            'Allowed External Domains',
            [$this, 'proxy_allowed_domains_field'],
            'wp-rest-auth-multi-proxy',
            'proxy_settings'
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
                <a href="?page=wp-rest-auth-multi&tab=proxy" class="nav-tab <?php echo $active_tab == 'proxy' ? 'nav-tab-active' : ''; ?>">🔒 API Proxy</a>
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
                } elseif ($active_tab == 'proxy') {
                    $this->render_proxy_tab();
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

    private function render_proxy_tab() {
        $proxy_settings = get_option(self::OPTION_PROXY_SETTINGS, []);
        $deployment_context = $this->detect_deployment_context();
        ?>
        <div class="proxy-settings">
            <?php
            // Show deployment context detection
            $this->render_deployment_context_info($deployment_context);
            ?>

            <div class="proxy-security-notice">
                <div class="notice notice-info inline">
                    <h3>🔒 Enhanced Security Mode</h3>
                    <p><strong>API Proxy Mode</strong> routes all API calls through your WordPress backend, keeping access tokens completely away from JavaScript. This prevents token theft from XSS attacks and provides maximum security.</p>

                    <h4>How it works:</h4>
                    <ol>
                        <li>Frontend sends requests to WordPress proxy endpoints (using HTTPOnly cookies)</li>
                        <li>WordPress backend handles OAuth2 tokens securely</li>
                        <li>WordPress makes actual API calls and returns sanitized responses</li>
                        <li>JavaScript never sees access tokens</li>
                    </ol>
                </div>
            </div>

            <?php do_settings_sections('wp-rest-auth-multi-proxy'); ?>
            <?php submit_button(); ?>

            <div class="proxy-examples">
                <h3>Usage Examples</h3>
                <div class="proxy-example-code">
                    <h4>Before (Direct Mode):</h4>
                    <pre><code>// JavaScript has access to tokens (security risk)
fetch('/wp-json/wp/v2/posts', {
    headers: { 'Authorization': 'Bearer ' + accessToken }
});
</code></pre>

                    <h4>After (Proxy Mode):</h4>
                    <pre><code>// Tokens stay on server (secure)
fetch('/wp-json/proxy/v1/api/wp/v2/posts', {
    credentials: 'include' // Uses HTTPOnly cookie
});
</code></pre>
                </div>
            </div>
        </div>
        <?php
    }

    private function detect_deployment_context() {
        $current_host = $_SERVER['HTTP_HOST'] ?? '';
        $wp_host = parse_url(home_url(), PHP_URL_HOST);
        $is_same_domain = $current_host === $wp_host;

        // Check if there are configured frontend URLs that differ
        $general_settings = self::get_general_settings();
        $cors_origins = $general_settings['cors_allowed_origins'] ?? '';
        $has_external_origins = !empty($cors_origins) && strpos($cors_origins, 'localhost') === false;

        return [
            'is_same_domain' => $is_same_domain,
            'has_external_origins' => $has_external_origins,
            'current_host' => $current_host,
            'wp_host' => $wp_host,
            'recommendation' => $has_external_origins ? 'proxy_recommended' : 'direct_ok'
        ];
    }

    private function render_deployment_context_info($context) {
        $is_recommended = $context['recommendation'] === 'proxy_recommended';
        $notice_class = $is_recommended ? 'notice-warning' : 'notice-info';
        ?>
        <div class="deployment-context">
            <div class="notice <?php echo $notice_class; ?> inline">
                <h4>🎯 Deployment Context Detection</h4>
                <p><strong>Current Host:</strong> <?php echo esc_html($context['current_host']); ?></p>
                <p><strong>WordPress Host:</strong> <?php echo esc_html($context['wp_host']); ?></p>

                <?php if ($is_recommended): ?>
                    <p><strong>✅ Recommendation:</strong> Enable API Proxy for enhanced security. Detected external frontend origins.</p>
                <?php else: ?>
                    <p><strong>ℹ️ Note:</strong> Direct mode is fine for same-domain deployments, but proxy mode provides better security.</p>
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
                <h3>🔒 API Proxy (Enhanced Security)</h3>
                <p><strong>What is API Proxy:</strong> Routes all API calls through WordPress backend, keeping access tokens completely away from JavaScript. This implements the OAuth2 Security Best Current Practice for Browser-Based Apps.</p>

                <h4>Security Benefits:</h4>
                <ul>
                    <li><strong>XSS Protection:</strong> Tokens can't be stolen by malicious scripts</li>
                    <li><strong>HTTPOnly Cookies:</strong> Session cookies aren't accessible to JavaScript</li>
                    <li><strong>Backend Token Storage:</strong> Access tokens never leave the server</li>
                    <li><strong>Confidential Client:</strong> Can use client_secret for OAuth2</li>
                </ul>

                <h4>Proxy Modes:</h4>
                <ul>
                    <li><strong>Full Proxy:</strong> All API calls go through WordPress backend</li>
                    <li><strong>Selective Proxy:</strong> Only specified endpoints (recommended)</li>
                    <li><strong>External APIs Only:</strong> Only external APIs are proxied</li>
                </ul>

                <h4>Usage Example:</h4>
                <pre><code>// Before (Direct Mode - tokens in JavaScript)
fetch('/wp-json/wp/v2/posts', {
    headers: { 'Authorization': 'Bearer ' + accessToken }
});

// After (Proxy Mode - tokens stay on server)
fetch('/wp-json/proxy/v1/api/wp/v2/posts', {
    credentials: 'include' // Uses HTTPOnly cookie
});
</code></pre>
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

    public function proxy_settings_section() {
        echo '<p>Configure API Proxy for enhanced security. When enabled, all API calls go through WordPress backend, keeping access tokens away from JavaScript.</p>';
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

    // Proxy Settings Fields
    public function proxy_enable_field() {
        $settings = get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
        $checked = isset($settings['enable_proxy']) && $settings['enable_proxy'];
        ?>
        <label>
            <input type="checkbox" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[enable_proxy]" value="1" <?php checked($checked); ?> id="proxy_enable" />
            <strong>Enable API Proxy for Maximum Security</strong>
        </label>
        <p class="description">
            🔒 <strong>Recommended for production environments.</strong> Routes API calls through WordPress backend, keeping access tokens away from JavaScript.
            <br><em>Note: This changes how your frontend application makes API calls.</em>
        </p>
        <?php
    }

    public function proxy_mode_field() {
        $settings = get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
        $mode = $settings['proxy_mode'] ?? 'selective';
        ?>
        <fieldset>
            <label>
                <input type="radio" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_mode]" value="full" <?php checked($mode, 'full'); ?> />
                <strong>Full Proxy</strong> - All API calls go through proxy
            </label><br>
            <label>
                <input type="radio" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_mode]" value="selective" <?php checked($mode, 'selective'); ?> />
                <strong>Selective Proxy</strong> - Only selected endpoints (recommended)
            </label><br>
            <label>
                <input type="radio" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_mode]" value="external_only" <?php checked($mode, 'external_only'); ?> />
                <strong>External APIs Only</strong> - Only proxy external API calls
            </label>
        </fieldset>
        <p class="description">Choose which API calls should be proxied for optimal balance of security and performance.</p>
        <?php
    }

    public function proxy_endpoints_field() {
        $settings = get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
        $endpoints = $settings['proxy_endpoints'] ?? [];
        ?>
        <fieldset>
            <legend><strong>Select endpoints to proxy:</strong></legend>
            <label>
                <input type="checkbox" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_endpoints][wp_api]" value="1" <?php checked(!empty($endpoints['wp_api'])); ?> />
                WordPress REST API (/wp/v2/*)
            </label><br>
            <label>
                <input type="checkbox" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_endpoints][user_sensitive]" value="1" <?php checked(!empty($endpoints['user_sensitive'])); ?> />
                User-sensitive endpoints (recommended)
            </label><br>
            <label>
                <input type="checkbox" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_endpoints][oauth2_api]" value="1" <?php checked(!empty($endpoints['oauth2_api'])); ?> />
                OAuth2 endpoints (/oauth2/v1/*)
            </label><br>
            <label>
                <input type="checkbox" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[proxy_endpoints][external_apis]" value="1" <?php checked(!empty($endpoints['external_apis'])); ?> />
                External APIs (configured below)
            </label>
        </fieldset>
        <p class="description">Select which types of API endpoints should be proxied through WordPress backend.</p>
        <?php
    }

    public function proxy_session_duration_field() {
        $settings = get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
        $value = $settings['session_duration'] ?? 3600;
        ?>
        <input type="number" name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[session_duration]" value="<?php echo esc_attr($value); ?>" min="300" max="86400" />
        <p class="description">How long proxy sessions remain valid in seconds. Default: 3600 (1 hour). Range: 300-86400 seconds.</p>
        <?php
    }

    public function proxy_allowed_domains_field() {
        $settings = get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
        $value = $settings['allowed_domains'] ?? "api.github.com\napi.stripe.com\napi.twilio.com";
        ?>
        <textarea name="<?php echo self::OPTION_PROXY_SETTINGS; ?>[allowed_domains]" class="large-text" rows="5"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">External domains that can be proxied. One domain per line. Only applies when "External APIs" is enabled above.</p>
        <div class="proxy-domain-examples">
            <strong>Examples:</strong>
            <ul style="margin-top: 5px;">
                <li><code>api.github.com</code> - GitHub API</li>
                <li><code>api.stripe.com</code> - Stripe API</li>
                <li><code>graph.microsoft.com</code> - Microsoft Graph API</li>
            </ul>
        </div>
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

    public function sanitize_proxy_settings($input) {
        $sanitized = [];

        $sanitized['enable_proxy'] = isset($input['enable_proxy']) && $input['enable_proxy'];

        if (isset($input['proxy_mode'])) {
            $allowed_modes = ['full', 'selective', 'external_only'];
            $mode = sanitize_text_field($input['proxy_mode']);
            $sanitized['proxy_mode'] = in_array($mode, $allowed_modes) ? $mode : 'selective';
        }

        if (isset($input['proxy_endpoints']) && is_array($input['proxy_endpoints'])) {
            $sanitized['proxy_endpoints'] = [
                'wp_api' => !empty($input['proxy_endpoints']['wp_api']),
                'user_sensitive' => !empty($input['proxy_endpoints']['user_sensitive']),
                'oauth2_api' => !empty($input['proxy_endpoints']['oauth2_api']),
                'external_apis' => !empty($input['proxy_endpoints']['external_apis'])
            ];
        }

        if (isset($input['session_duration'])) {
            $duration = intval($input['session_duration']);
            $sanitized['session_duration'] = max(300, min(86400, $duration));
        }

        if (isset($input['allowed_domains'])) {
            $domains = sanitize_textarea_field($input['allowed_domains']);
            // Validate domains
            $domain_lines = array_filter(array_map('trim', explode("\n", $domains)));
            $valid_domains = [];
            foreach ($domain_lines as $domain) {
                if (filter_var('http://' . $domain, FILTER_VALIDATE_URL)) {
                    $valid_domains[] = $domain;
                } else {
                    add_settings_error(
                        self::OPTION_PROXY_SETTINGS,
                        'invalid_domain',
                        sprintf('Invalid domain format: %s', esc_html($domain))
                    );
                }
            }
            $sanitized['allowed_domains'] = implode("\n", $valid_domains);
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

    public static function get_proxy_settings() {
        return get_option(self::OPTION_PROXY_SETTINGS, self::get_proxy_settings_defaults());
    }

    public static function get_proxy_settings_defaults() {
        return [
            'enable_proxy' => false,
            'proxy_mode' => 'selective',
            'proxy_endpoints' => [
                'wp_api' => false,
                'user_sensitive' => true, // Recommended default
                'oauth2_api' => false,
                'external_apis' => false
            ],
            'session_duration' => 3600,
            'allowed_domains' => "api.github.com\napi.stripe.com\napi.twilio.com",
            'enable_cors_proxy' => true
        ];
    }
}