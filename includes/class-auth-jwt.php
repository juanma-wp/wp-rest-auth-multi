<?php
/**
 * JWT Authentication class with refresh token support
 */

if (!defined('ABSPATH')) {
    exit;
}

class Auth_JWT {

    const ISSUER = 'wp-rest-auth-multi';
    const REFRESH_COOKIE_NAME = 'wp_refresh_token';

    public function register_routes(): void {
        register_rest_route('jwt/v1', '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'issue_token'],
            'permission_callback' => '__return_true',
            'args' => [
                'username' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_user'
                ],
                'password' => [
                    'required' => true,
                    'type' => 'string'
                ]
            ]
        ]);

        register_rest_route('jwt/v1', '/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'refresh_access_token'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('jwt/v1', '/logout', [
            'methods' => 'POST',
            'callback' => [$this, 'logout'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('jwt/v1', '/verify', [
            'methods' => 'GET',
            'callback' => [$this, 'whoami'],
            'permission_callback' => '__return_true'
        ]);

        // Add CORS support
        add_action('rest_api_init', [$this, 'add_cors_support']);
    }

    public function add_cors_support(): void {
        remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
        add_filter('rest_pre_serve_request', function($served, $result, $request, $server) {
            wp_auth_multi_maybe_add_cors_headers();
            return $served;
        }, 15, 4);
    }

    public function issue_token(WP_REST_Request $request) {
        wp_auth_multi_maybe_add_cors_headers();

        $username = $request->get_param('username');
        $password = $request->get_param('password');

        if (empty($username) || empty($password)) {
            return wp_auth_multi_error_response(
                'missing_credentials',
                'Username and password are required',
                400
            );
        }

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            return wp_auth_multi_error_response(
                'invalid_credentials',
                'Invalid username or password',
                401
            );
        }

        // Generate access token (JWT)
        $now = time();
        $access_claims = [
            'iss' => self::ISSUER,
            'sub' => (string)$user->ID,
            'iat' => $now,
            'exp' => $now + WP_JWT_ACCESS_TTL,
            'roles' => array_values($user->roles),
            'jti' => wp_auth_multi_generate_token(16)
        ];

        $access_token = wp_auth_multi_jwt_encode($access_claims, WP_JWT_AUTH_SECRET);

        // Generate refresh token
        $refresh_token = wp_auth_multi_generate_token(64);
        $refresh_expires = $now + WP_JWT_REFRESH_TTL;

        // Store refresh token in database
        $this->store_refresh_token($user->ID, $refresh_token, $refresh_expires);

        // Set refresh token as HttpOnly cookie
        wp_auth_multi_set_cookie(
            self::REFRESH_COOKIE_NAME,
            $refresh_token,
            $refresh_expires,
            '/wp-json/jwt/v1/',
            true,
            true,
            'Strict'
        );

        return wp_auth_multi_success_response([
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => WP_JWT_ACCESS_TTL,
            'user' => wp_auth_multi_format_user_data($user)
        ], 'Login successful', 200);
    }

    public function refresh_access_token(WP_REST_Request $request) {
        wp_auth_multi_maybe_add_cors_headers();

        $refresh_token = $_COOKIE[self::REFRESH_COOKIE_NAME] ?? '';

        if (empty($refresh_token)) {
            return wp_auth_multi_error_response(
                'missing_refresh_token',
                'Refresh token not found',
                401
            );
        }

        $token_data = $this->validate_refresh_token($refresh_token);

        if (is_wp_error($token_data)) {
            return $token_data;
        }

        $user = get_user_by('id', $token_data['user_id']);
        if (!$user) {
            return wp_auth_multi_error_response(
                'user_not_found',
                'User not found',
                401
            );
        }

        // Generate new access token
        $now = time();
        $access_claims = [
            'iss' => self::ISSUER,
            'sub' => (string)$user->ID,
            'iat' => $now,
            'exp' => $now + WP_JWT_ACCESS_TTL,
            'roles' => array_values($user->roles),
            'jti' => wp_auth_multi_generate_token(16)
        ];

        $access_token = wp_auth_multi_jwt_encode($access_claims, WP_JWT_AUTH_SECRET);

        // Optionally rotate refresh token for better security
        if (apply_filters('wp_auth_multi_rotate_refresh_token', true)) {
            $new_refresh_token = wp_auth_multi_generate_token(64);
            $refresh_expires = $now + WP_JWT_REFRESH_TTL;

            // Update refresh token in database
            $this->update_refresh_token($token_data['id'], $new_refresh_token, $refresh_expires);

            // Set new refresh token cookie
            wp_auth_multi_set_cookie(
                self::REFRESH_COOKIE_NAME,
                $new_refresh_token,
                $refresh_expires,
                '/wp-json/jwt/v1/',
                true,
                true,
                'Strict'
            );
        }

        return wp_auth_multi_success_response([
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => WP_JWT_ACCESS_TTL
        ], 'Token refreshed successfully', 200);
    }

    public function logout(WP_REST_Request $request) {
        wp_auth_multi_maybe_add_cors_headers();

        $refresh_token = $_COOKIE[self::REFRESH_COOKIE_NAME] ?? '';

        if (!empty($refresh_token)) {
            $this->revoke_refresh_token($refresh_token);
        }

        // Delete refresh token cookie
        wp_auth_multi_delete_cookie(self::REFRESH_COOKIE_NAME, '/wp-json/jwt/v1/');

        return wp_auth_multi_success_response([], 'Logout successful', 200);
    }

    public function whoami(WP_REST_Request $request) {
        wp_auth_multi_maybe_add_cors_headers();

        $user = wp_get_current_user();

        if (!$user || !$user->ID) {
            return wp_auth_multi_error_response(
                'not_authenticated',
                'You are not authenticated',
                401
            );
        }

        return wp_auth_multi_success_response([
            'authenticated' => true,
            'user' => wp_auth_multi_format_user_data($user)
        ], 'Token is valid', 200);
    }

    public function authenticate_bearer(string $token) {
        $payload = wp_auth_multi_jwt_decode($token, WP_JWT_AUTH_SECRET);

        if (is_wp_error($payload)) {
            return $payload;
        }

        $user_id = (int)($payload['sub'] ?? 0);
        if (!$user_id) {
            return new WP_Error(
                'jwt_no_subject',
                'Token has no subject',
                ['status' => 401]
            );
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return new WP_Error(
                'jwt_user_not_found',
                'User not found',
                ['status' => 401]
            );
        }

        wp_set_current_user($user_id);
        return true;
    }

    private function store_refresh_token(int $user_id, string $refresh_token, int $expires_at): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_multi_hash_token($refresh_token, WP_JWT_AUTH_SECRET);

        $result = $wpdb->insert(
            $table_name,
            [
                'user_id' => $user_id,
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'issued_at' => time(),
                'user_agent' => wp_auth_multi_get_user_agent(),
                'ip_address' => wp_auth_multi_get_ip_address()
            ],
            ['%d', '%s', '%d', '%d', '%s', '%s']
        );

        return $result !== false;
    }

    private function validate_refresh_token(string $refresh_token) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_multi_hash_token($refresh_token, WP_JWT_AUTH_SECRET);
        $now = time();

        $token_data = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$table_name}
                 WHERE token_hash = %s
                 AND expires_at > %d
                 AND revoked_at IS NULL
                 LIMIT 1",
                $token_hash,
                $now
            ),
            ARRAY_A
        );

        if (!$token_data) {
            return new WP_Error(
                'invalid_refresh_token',
                'Invalid or expired refresh token',
                ['status' => 401]
            );
        }

        return $token_data;
    }

    private function update_refresh_token(int $token_id, string $new_refresh_token, int $expires_at): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_multi_hash_token($new_refresh_token, WP_JWT_AUTH_SECRET);

        $result = $wpdb->update(
            $table_name,
            [
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'issued_at' => time(),
                'user_agent' => wp_auth_multi_get_user_agent(),
                'ip_address' => wp_auth_multi_get_ip_address()
            ],
            ['id' => $token_id],
            ['%s', '%d', '%d', '%s', '%s'],
            ['%d']
        );

        return $result !== false;
    }

    private function revoke_refresh_token(string $refresh_token): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_multi_hash_token($refresh_token, WP_JWT_AUTH_SECRET);

        $result = $wpdb->update(
            $table_name,
            ['revoked_at' => time()],
            ['token_hash' => $token_hash],
            ['%d'],
            ['%s']
        );

        return $result !== false;
    }

    public function clean_expired_tokens(): void {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $now = time();

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$table_name} WHERE expires_at < %d OR revoked_at IS NOT NULL",
                $now
            )
        );
    }

    public function get_user_refresh_tokens(int $user_id): array {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, issued_at, expires_at, user_agent, ip_address
                 FROM {$table_name}
                 WHERE user_id = %d AND expires_at > %d AND revoked_at IS NULL
                 ORDER BY issued_at DESC",
                $user_id,
                time()
            ),
            ARRAY_A
        );
    }

    public function revoke_user_token(int $user_id, int $token_id): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';

        $result = $wpdb->update(
            $table_name,
            ['revoked_at' => time()],
            ['id' => $token_id, 'user_id' => $user_id],
            ['%d'],
            ['%d', '%d']
        );

        return $result !== false;
    }
}