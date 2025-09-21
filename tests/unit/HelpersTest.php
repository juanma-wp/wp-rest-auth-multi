<?php

use PHPUnit\Framework\TestCase;

/**
 * Tests for helper functions
 */
class HelpersTest extends TestCase
{
    public function testJWTEncodeDecode(): void
    {
        // Load helpers if not already loaded
        if (!function_exists('wp_auth_multi_jwt_encode')) {
            require_once dirname(__DIR__, 2) . '/includes/helpers.php';
        }

        $secret = 'test-secret';
        $claims = [
            'user_id' => 123,
            'exp' => time() + 3600
        ];

        $jwt = wp_auth_multi_jwt_encode($claims, $secret);
        $this->assertNotEmpty($jwt);
        $this->assertCount(3, explode('.', $jwt));

        $decoded = wp_auth_multi_jwt_decode($jwt, $secret);
        $this->assertIsArray($decoded);
        $this->assertEquals(123, $decoded['user_id']);
    }

    public function testBase64UrlEncode(): void
    {
        if (!function_exists('wp_auth_multi_base64url_encode')) {
            require_once dirname(__DIR__, 2) . '/includes/helpers.php';
        }

        $data = 'Hello World!';
        $encoded = wp_auth_multi_base64url_encode($data);
        $decoded = wp_auth_multi_base64url_decode($encoded);

        $this->assertEquals($data, $decoded);
    }

    public function testGenerateToken(): void
    {
        if (!function_exists('wp_auth_multi_generate_token')) {
            require_once dirname(__DIR__, 2) . '/includes/helpers.php';
        }

        $token = wp_auth_multi_generate_token(32);
        $this->assertEquals(32, strlen($token));
    }
}