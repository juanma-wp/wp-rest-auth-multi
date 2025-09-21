# WP REST Multi Auth (JWT + OAuth2)

A comprehensive WordPress plugin that provides both JWT with refresh tokens (HttpOnly cookies) and OAuth2 authentication for the WordPress REST API.

## Features

- **JWT Authentication** with refresh tokens stored as HttpOnly cookies
- **OAuth2 Authorization Code flow** (simplified for demo)
- Secure token storage and management
- CORS support for frontend applications
- Token revocation and cleanup
- User-friendly admin interface

## Installation

1. Download or clone this plugin to your `wp-content/plugins/` directory
2. Add the following constants to your `wp-config.php` file:

```php
define('WP_JWT_AUTH_SECRET', 'your-very-long-and-random-secret-key-here');
define('WP_JWT_ACCESS_TTL', 900);     // 15 minutes (optional)
define('WP_JWT_REFRESH_TTL', 1209600); // 14 days (optional)
```

3. Activate the plugin through the WordPress admin interface

## JWT Authentication

### Endpoints

#### 1. Get Access Token
```bash
POST /wp-json/jwt/v1/token
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "roles": ["administrator"]
  }
}
```

The refresh token is automatically set as an HttpOnly cookie.

#### 2. Refresh Access Token
```bash
POST /wp-json/jwt/v1/refresh
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### 3. Logout
```bash
POST /wp-json/jwt/v1/logout
```

#### 4. Verify Token
```bash
GET /wp-json/jwt/v1/verify
Authorization: Bearer <access_token>
```

### Using JWT with REST API

Once you have an access token, include it in the Authorization header:

```bash
curl -X POST "https://yoursite.com/wp-json/wp/v2/posts" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"title": "My New Post", "content": "Post content here"}'
```

## OAuth2 Authentication

### Demo Client

The plugin creates a demo OAuth2 client automatically:
- **Client ID:** `demo-client`
- **Client Secret:** `demo-secret`
- **Redirect URIs:** `http://localhost:3000/callback`, `http://localhost:5173/callback`

### Authorization Code Flow

#### 1. Authorization Request
```
GET /wp-json/oauth2/v1/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&state=xyz123
```

#### 2. Exchange Code for Token
```bash
POST /wp-json/oauth2/v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<authorization_code>&redirect_uri=http://localhost:3000/callback&client_id=demo-client&client_secret=demo-secret
```

#### 3. Get User Info
```bash
GET /wp-json/oauth2/v1/userinfo
Authorization: Bearer <access_token>
```

## Frontend Integration Examples

### JavaScript (Fetch API)

```javascript
// Get JWT access token
async function login(username, password) {
  const response = await fetch('/wp-json/jwt/v1/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include', // Important for refresh token cookie
    body: JSON.stringify({ username, password })
  });

  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    return data;
  }
  throw new Error('Login failed');
}

// Refresh access token
async function refreshToken() {
  const response = await fetch('/wp-json/jwt/v1/refresh', {
    method: 'POST',
    credentials: 'include' // Include refresh token cookie
  });

  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    return data.access_token;
  }
  throw new Error('Token refresh failed');
}

// Make authenticated API calls
async function apiCall(url, options = {}) {
  let token = localStorage.getItem('access_token');

  const response = await fetch(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers
    }
  });

  // If token expired, try to refresh
  if (response.status === 401) {
    try {
      token = await refreshToken();
      return fetch(url, {
        ...options,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...options.headers
        }
      });
    } catch (error) {
      // Redirect to login
      window.location.href = '/login';
    }
  }

  return response;
}
```

### React Hook Example

```javascript
import { useState, useEffect } from 'react';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const login = async (username, password) => {
    const response = await fetch('/wp-json/jwt/v1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('access_token', data.access_token);
      setUser(data.user);
      return data;
    }
    throw new Error('Login failed');
  };

  const logout = async () => {
    await fetch('/wp-json/jwt/v1/logout', {
      method: 'POST',
      credentials: 'include'
    });
    localStorage.removeItem('access_token');
    setUser(null);
  };

  const refreshToken = async () => {
    try {
      const response = await fetch('/wp-json/jwt/v1/refresh', {
        method: 'POST',
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
        return data.access_token;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
    }
    return null;
  };

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      // Verify token on app load
      fetch('/wp-json/jwt/v1/verify', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      .then(response => response.json())
      .then(data => {
        if (data.authenticated) {
          setUser(data.user);
        }
      })
      .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  return { user, login, logout, refreshToken, loading };
}
```

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Secure Cookies**: Refresh tokens use HttpOnly, Secure, and SameSite=Strict cookies
3. **Token Rotation**: Refresh tokens are rotated on each use (configurable)
4. **Short-lived Access Tokens**: Default 15-minute expiration
5. **CORS Configuration**: Configure allowed origins properly

## Configuration

### CORS Origins
```php
add_filter('wp_auth_multi_cors_origins', function($origins) {
    return array_merge($origins, [
        'https://yourfrontend.com',
        'https://anotherdomain.com'
    ]);
});
```

### Disable Token Rotation
```php
add_filter('wp_auth_multi_rotate_refresh_token', '__return_false');
```

## Database Tables

The plugin creates a `wp_jwt_refresh_tokens` table to store refresh tokens securely with the following columns:
- `id` - Primary key
- `user_id` - WordPress user ID
- `token_hash` - Hashed refresh token
- `expires_at` - Expiration timestamp
- `revoked_at` - Revocation timestamp (if revoked)
- `issued_at` - Issue timestamp
- `user_agent` - User agent string
- `ip_address` - IP address

## Testing

### Test JWT Authentication

```bash
# 1. Get token
curl -X POST "http://yoursite.local/wp-json/jwt/v1/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  -c cookies.txt

# 2. Use token to create a post
curl -X POST "http://yoursite.local/wp-json/wp/v2/posts" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Post","status":"draft"}'

# 3. Refresh token
curl -X POST "http://yoursite.local/wp-json/jwt/v1/refresh" \
  -b cookies.txt

# 4. Logout
curl -X POST "http://yoursite.local/wp-json/jwt/v1/logout" \
  -b cookies.txt
```

### Test OAuth2 Flow

```bash
# 1. Get authorization code (requires login in browser first)
# Visit: http://yoursite.local/wp-json/oauth2/v1/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&state=test

# 2. Exchange code for token
curl -X POST "http://yoursite.local/wp-json/oauth2/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:3000/callback&client_id=demo-client&client_secret=demo-secret"

# 3. Get user info
curl -X GET "http://yoursite.local/wp-json/oauth2/v1/userinfo" \
  -H "Authorization: Bearer <access_token>"
```

## Support

For issues and feature requests, please create an issue in the project repository.

## License

GPL v2 or later