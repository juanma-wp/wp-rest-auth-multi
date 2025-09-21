<?php
/**
 * WordPress OAuth2 Client Update Script
 *
 * This script updates the demo OAuth2 client to include the correct redirect URIs.
 * Place this file in your WordPress root directory and access it via browser.
 */

// Load WordPress
require_once('wp-config.php');
require_once('wp-load.php');

// Check if user is admin (simple security check)
if (!current_user_can('manage_options')) {
    wp_die('You must be an administrator to run this script.');
}

// Update OAuth2 clients
$clients = get_option('oauth2_clients', []);

$clients['demo-client'] = [
    'client_secret' => wp_hash_password('demo-secret'),
    'redirect_uris' => [
        'http://localhost:3000/callback',
        'http://localhost:5173/callback',
        'http://localhost:5174/callback',
        'https://example.com/callback'
    ]
];

$result = update_option('oauth2_clients', $clients);

if ($result) {
    echo '<h1>✅ OAuth2 Client Updated Successfully!</h1>';
    echo '<p>The demo-client now includes the following redirect URIs:</p>';
    echo '<ul>';
    foreach ($clients['demo-client']['redirect_uris'] as $uri) {
        echo "<li>$uri</li>";
    }
    echo '</ul>';
    echo '<p><strong>You can now try the OAuth2 demo again.</strong></p>';
} else {
    echo '<h1>❌ Update Failed</h1>';
    echo '<p>Could not update OAuth2 client configuration.</p>';
}

echo '<hr>';
echo '<p><strong>Current OAuth2 Clients:</strong></p>';
echo '<pre>' . print_r($clients, true) . '</pre>';
?>