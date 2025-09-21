<?php

use PHPUnit\Framework\TestCase;

/**
 * Unit tests
 */
class PluginTest extends TestCase
{
    public function testPluginLoaded(): void
    {
        $this->assertTrue(class_exists('WP_REST_Auth_Multi'));
    }

    public function testWordPressFunctions(): void
    {
        $this->assertTrue(function_exists('wp_create_nonce'));
        $this->assertTrue(function_exists('get_option'));
    }

    public function testJWTConstantsDefined(): void
    {
        $this->assertTrue(defined('WP_JWT_AUTH_SECRET'));
        $this->assertNotEmpty(WP_JWT_AUTH_SECRET);
    }
}