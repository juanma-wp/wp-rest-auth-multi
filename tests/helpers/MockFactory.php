<?php

namespace WPRestAuthMulti\Tests\Helpers;

/**
 * Factory for creating mock objects and data for tests
 */
class MockFactory
{
    /**
     * Create mock admin settings data
     */
    public static function createMockAdminSettings(): array
    {
        return [
            'jwt_settings' => [
                'secret_key' => 'test-secret-key-for-testing-purposes-only',
                'access_token_expiry' => 3600,
                'refresh_token_expiry' => 86400
            ],
            'oauth2_settings' => [
                'clients' => [
                    'test-client' => [
                        'name' => 'Test Client',
                        'redirect_uris' => [
                            'http://localhost:3000/callback',
                            'http://localhost:5173/callback'
                        ],
                        'created_at' => '2023-01-01 12:00:00'
                    ]
                ]
            ],
            'general_settings' => [
                'enable_debug_logging' => false,
                'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173"
            ]
        ];
    }

    /**
     * Create mock OAuth2 client data
     */
    public static function createMockOAuth2Client($client_id = 'test-client'): array
    {
        return [
            'name' => 'Test Application',
            'redirect_uris' => [
                'http://localhost:3000/callback',
                'http://localhost:5173/callback'
            ],
            'created_at' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Create mock OAuth2 authorization code
     */
    public static function createMockAuthCode($client_id = 'test-client', $user_id = 1): array
    {
        return [
            'code' => 'test-auth-code-' . uniqid(),
            'client_id' => $client_id,
            'user_id' => $user_id,
            'scopes' => ['read', 'write'],
            'redirect_uri' => 'http://localhost:3000/callback',
            'expires_at' => time() + 600, // 10 minutes
            'code_challenge' => base64_encode('test-code-verifier'),
            'code_challenge_method' => 'S256'
        ];
    }

    /**
     * Create mock OAuth2 access token data
     */
    public static function createMockAccessToken($user_id = 1, $scopes = ['read']): array
    {
        return [
            'user_id' => $user_id,
            'client_id' => 'test-client',
            'scopes' => $scopes,
            'expires_at' => time() + 3600,
            'created_at' => time()
        ];
    }

    /**
     * Create mock JWT payload
     */
    public static function createMockJWTPayload($user_id = 1, $exp = null): array
    {
        if ($exp === null) {
            $exp = time() + 3600;
        }

        return [
            'iss' => 'test-issuer',
            'iat' => time(),
            'exp' => $exp,
            'data' => [
                'user' => [
                    'id' => $user_id
                ]
            ]
        ];
    }

    /**
     * Create mock refresh token data
     */
    public static function createMockRefreshToken($user_id = 1): array
    {
        return [
            'token' => 'refresh_' . bin2hex(random_bytes(32)),
            'user_id' => $user_id,
            'expires_at' => time() + 86400 * 30, // 30 days
            'created_at' => time()
        ];
    }

    /**
     * Create mock WordPress REST request
     */
    public static function createMockWPRestRequest($method = 'GET', $route = '/test'): \stdClass
    {
        $request = new \stdClass();
        $request->method = $method;
        $request->route = $route;
        $request->params = [];
        $request->headers = [];

        return $request;
    }

    /**
     * Create mock WordPress user
     */
    public static function createMockWPUser($id = 1, $login = 'testuser'): \stdClass
    {
        $user = new \stdClass();
        $user->ID = $id;
        $user->user_login = $login;
        $user->user_email = $login . '@example.com';
        $user->display_name = ucfirst($login);
        $user->roles = ['subscriber'];

        return $user;
    }

    /**
     * Create mock WordPress error
     */
    public static function createMockWPError($code = 'test_error', $message = 'Test error', $data = null): \WP_Error
    {
        return new \WP_Error($code, $message, $data);
    }

    /**
     * Create mock HTTP response
     */
    public static function createMockHTTPResponse($body = '', $status = 200, $headers = []): array
    {
        return [
            'body' => $body,
            'response' => [
                'code' => $status,
                'message' => $status === 200 ? 'OK' : 'Error'
            ],
            'headers' => $headers
        ];
    }

    /**
     * Create mock OAuth2 consent form data
     */
    public static function createMockConsentData($client_id = 'test-client'): array
    {
        return [
            'client_id' => $client_id,
            'response_type' => 'code',
            'redirect_uri' => 'http://localhost:3000/callback',
            'scope' => 'read write',
            'state' => 'test-state-' . uniqid(),
            'code_challenge' => base64_encode('test-code-verifier'),
            'code_challenge_method' => 'S256'
        ];
    }

    /**
     * Create mock database table data
     */
    public static function createMockTableData($table_name = 'test_table'): array
    {
        return [
            'table_name' => $table_name,
            'columns' => [
                'id' => 'int(11) NOT NULL AUTO_INCREMENT',
                'user_id' => 'bigint(20) NOT NULL',
                'token' => 'varchar(255) NOT NULL',
                'expires_at' => 'datetime NOT NULL',
                'created_at' => 'datetime DEFAULT CURRENT_TIMESTAMP'
            ],
            'primary_key' => 'id',
            'indexes' => [
                'user_id',
                'token',
                'expires_at'
            ]
        ];
    }

    /**
     * Create mock CORS headers
     */
    public static function createMockCORSHeaders($origin = 'http://localhost:3000'): array
    {
        return [
            'Access-Control-Allow-Origin' => $origin,
            'Access-Control-Allow-Methods' => 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers' => 'Authorization, Content-Type, X-Requested-With',
            'Access-Control-Allow-Credentials' => 'true',
            'Access-Control-Max-Age' => '86400'
        ];
    }

    /**
     * Create mock server environment
     */
    public static function setupMockServerEnvironment($overrides = []): void
    {
        $defaults = [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_HOST' => 'localhost',
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => '80',
            'HTTPS' => '',
            'HTTP_USER_AGENT' => 'PHPUnit Test',
            'REMOTE_ADDR' => '127.0.0.1'
        ];

        foreach (array_merge($defaults, $overrides) as $key => $value) {
            $_SERVER[$key] = $value;
        }
    }

    /**
     * Create mock validation errors
     */
    public static function createMockValidationErrors(): array
    {
        return [
            'required_field' => 'This field is required.',
            'invalid_email' => 'Please enter a valid email address.',
            'password_too_short' => 'Password must be at least 8 characters long.',
            'invalid_url' => 'Please enter a valid URL.',
            'numeric_only' => 'This field must contain only numbers.'
        ];
    }

    /**
     * Create mock API endpoints data
     */
    public static function createMockAPIEndpoints(): array
    {
        return [
            'jwt' => [
                'login' => '/wp-json/wp-rest-auth-multi/v1/jwt/login',
                'refresh' => '/wp-json/wp-rest-auth-multi/v1/jwt/refresh',
                'validate' => '/wp-json/wp-rest-auth-multi/v1/jwt/validate'
            ],
            'oauth2' => [
                'authorize' => '/wp-json/wp-rest-auth-multi/v1/oauth2/authorize',
                'token' => '/wp-json/wp-rest-auth-multi/v1/oauth2/token',
                'userinfo' => '/wp-json/wp-rest-auth-multi/v1/oauth2/userinfo'
            ]
        ];
    }
}