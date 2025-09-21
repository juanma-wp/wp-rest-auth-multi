<?php
/**
 * Helper functions for JWT operations and general utilities
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Generate a JWT token with HS256 algorithm
 *
 * @param array $claims The payload claims
 * @param string $secret The secret key for signing
 * @return string The JWT token
 */
function wp_auth_multi_jwt_encode(array $claims, string $secret): string {
    if (empty($secret)) {
        wp_die('JWT secret is required for token generation');
    }

    $header = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];

    $segments = [
        wp_auth_multi_base64url_encode(json_encode($header)),
        wp_auth_multi_base64url_encode(json_encode($claims))
    ];

    $signing_input = implode('.', $segments);
    $signature = hash_hmac('sha256', $signing_input, $secret, true);
    $segments[] = wp_auth_multi_base64url_encode($signature);

    return implode('.', $segments);
}

/**
 * Decode and verify a JWT token
 *
 * @param string $jwt The JWT token to decode
 * @param string $secret The secret key for verification
 * @return array|WP_Error The decoded claims or error
 */
function wp_auth_multi_jwt_decode(string $jwt, string $secret) {
    if (empty($secret)) {
        return new WP_Error('jwt_secret_missing', 'JWT secret is required', ['status' => 500]);
    }

    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return new WP_Error('jwt_malformed', 'Token is malformed', ['status' => 401]);
    }

    list($header64, $payload64, $signature64) = $parts;

    $header = json_decode(wp_auth_multi_base64url_decode($header64), true);
    $payload = json_decode(wp_auth_multi_base64url_decode($payload64), true);
    $signature = wp_auth_multi_base64url_decode($signature64);

    if (!$header || !$payload) {
        return new WP_Error('jwt_invalid_json', 'Invalid JSON in token', ['status' => 401]);
    }

    // Verify algorithm
    if (($header['alg'] ?? '') !== 'HS256') {
        return new WP_Error('jwt_algorithm_unsupported', 'Unsupported algorithm', ['status' => 401]);
    }

    // Verify signature
    $expected_signature = hash_hmac('sha256', "$header64.$payload64", $secret, true);
    if (!hash_equals($expected_signature, $signature)) {
        return new WP_Error('jwt_signature_invalid', 'Invalid token signature', ['status' => 401]);
    }

    // Check expiration
    if (isset($payload['exp']) && time() >= (int)$payload['exp']) {
        return new WP_Error('jwt_expired', 'Token has expired', ['status' => 401]);
    }

    // Check not before
    if (isset($payload['nbf']) && time() < (int)$payload['nbf']) {
        return new WP_Error('jwt_not_yet_valid', 'Token not yet valid', ['status' => 401]);
    }

    return $payload;
}

/**
 * Base64 URL-safe encode
 *
 * @param string $data The data to encode
 * @return string The encoded data
 */
function wp_auth_multi_base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64 URL-safe decode
 *
 * @param string $data The data to decode
 * @return string The decoded data
 */
function wp_auth_multi_base64url_decode(string $data): string {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

/**
 * Generate a secure random token
 *
 * @param int $length The length of the token
 * @return string The random token
 */
function wp_auth_multi_generate_token(int $length = 64): string {
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes($length / 2));
    }

    // Fallback to WordPress function
    return wp_generate_password($length, true, true);
}

/**
 * Hash a refresh token for storage
 *
 * @param string $token The token to hash
 * @param string $secret The secret for hashing
 * @return string The hashed token
 */
function wp_auth_multi_hash_token(string $token, string $secret): string {
    return hash_hmac('sha256', $token, $secret);
}

/**
 * Get the user's IP address
 *
 * @return string The IP address
 */
function wp_auth_multi_get_ip_address(): string {
    $ip_keys = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];

    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            $ip = $_SERVER[$key];
            if (strpos($ip, ',') !== false) {
                $ip = explode(',', $ip)[0];
            }
            $ip = trim($ip);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }

    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Get the user agent
 *
 * @return string The user agent
 */
function wp_auth_multi_get_user_agent(): string {
    return sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
}

/**
 * Set a secure HttpOnly cookie
 *
 * @param string $name Cookie name
 * @param string $value Cookie value
 * @param int $expires Expiration timestamp
 * @param string $path Cookie path
 * @param bool $secure Use secure flag
 * @param bool $httponly Use httponly flag
 * @param string $samesite SameSite attribute
 * @return bool Success
 */
function wp_auth_multi_set_cookie(
    string $name,
    string $value,
    int $expires,
    string $path = '/',
    bool $secure = true,
    bool $httponly = true,
    string $samesite = 'Strict'
): bool {
    if (headers_sent()) {
        return false;
    }

    $options = [
        'expires' => $expires,
        'path' => $path,
        'domain' => '',
        'secure' => $secure && is_ssl(),
        'httponly' => $httponly,
        'samesite' => $samesite
    ];

    return setcookie($name, $value, $options);
}

/**
 * Delete a cookie by setting it to expire
 *
 * @param string $name Cookie name
 * @param string $path Cookie path
 * @return bool Success
 */
function wp_auth_multi_delete_cookie(string $name, string $path = '/'): bool {
    return wp_auth_multi_set_cookie($name, '', time() - 3600, $path);
}

/**
 * Validate CORS origin
 *
 * @param string $origin The origin to validate
 * @return bool Whether the origin is allowed
 */
function wp_auth_multi_is_valid_origin(string $origin): bool {
    $allowed_origins = apply_filters('wp_auth_multi_cors_origins', [
        home_url(),
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:8080'
    ]);

    return in_array(rtrim($origin, '/'), $allowed_origins, true);
}

/**
 * Add CORS headers if needed
 */
function wp_auth_multi_maybe_add_cors_headers(): void {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if ($origin && wp_auth_multi_is_valid_origin($origin)) {
        header("Access-Control-Allow-Origin: $origin");
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-WP-Nonce');
        header('Access-Control-Max-Age: 86400');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            status_header(200);
            exit;
        }
    }
}