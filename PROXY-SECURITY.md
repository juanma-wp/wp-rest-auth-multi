# API Proxy - Enhanced Security Mode

## 🔒 Overview

The API Proxy feature implements the **OAuth2 Security Best Current Practice for Browser-Based Apps**, providing maximum security by keeping access tokens completely away from JavaScript code.

## 🚨 Security Benefits

### Traditional Approach (Vulnerable)
```javascript
// ❌ Tokens in JavaScript = Security Risk
const accessToken = localStorage.getItem('access_token');
fetch('/wp-json/wp/v2/posts', {
    headers: { 'Authorization': 'Bearer ' + accessToken }
});
```

**Vulnerabilities:**
- XSS attacks can steal tokens from localStorage/sessionStorage
- JavaScript has access to sensitive tokens
- Tokens transmitted in browser URL/headers

### Proxy Mode (Secure)
```javascript
// ✅ Tokens stay on server = Maximum Security
fetch('/wp-json/proxy/v1/api/wp/v2/posts', {
    credentials: 'include' // Uses HTTPOnly cookie
});
```

**Security Features:**
- Access tokens never reach JavaScript
- HTTPOnly cookies can't be accessed by scripts
- Backend-only token storage and management
- XSS-resistant architecture

## 📋 Configuration

### Enable API Proxy
1. Go to **WordPress Admin → Settings → WP REST Auth Multi**
2. Click the **🔒 API Proxy** tab
3. Check **"Enable API Proxy for Maximum Security"**
4. Choose your proxy mode:
   - **Selective Proxy** (recommended)
   - **Full Proxy** (maximum security)
   - **External APIs Only** (hybrid approach)

### Proxy Modes

#### 1. Selective Proxy (Recommended)
Only specified endpoint types are proxied:
```
✅ User-sensitive endpoints (default: enabled)
☐ WordPress REST API (/wp/v2/*)
☐ OAuth2 endpoints (/oauth2/v1/*)
☐ External APIs
```

#### 2. Full Proxy (Maximum Security)
All API calls go through the proxy:
```
✅ All WordPress REST API endpoints
✅ All OAuth2 endpoints
✅ All external APIs (if configured)
```

#### 3. External APIs Only
Only external API calls are proxied:
```
☐ WordPress REST API (direct)
☐ OAuth2 endpoints (direct)
✅ External APIs only
```

## 🔧 Implementation Guide

### 1. Frontend Authentication

#### Step 1: Authenticate User (OAuth2/JWT)
```javascript
// Standard OAuth2 or JWT authentication
const authResponse = await fetch('/wp-json/oauth2/v1/token', {
    method: 'POST',
    body: JSON.stringify({
        grant_type: 'authorization_code',
        code: authCode,
        // ... other OAuth2 params
    })
});
```

#### Step 2: Create Proxy Session
```javascript
// After successful authentication, create proxy session
const sessionResponse = await fetch('/wp-json/proxy/v1/session/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
        auth_method: 'oauth2', // or 'jwt'
        credentials: {
            access_token: authResponse.access_token,
            refresh_token: authResponse.refresh_token // for OAuth2
        }
    })
});

if (sessionResponse.ok) {
    console.log('Proxy session created! 🔒');
    // Now all API calls go through proxy
}
```

#### Step 3: Make Proxied API Calls
```javascript
// All subsequent API calls use proxy endpoints
const posts = await fetch('/wp-json/proxy/v1/api/wp/v2/posts', {
    credentials: 'include' // Essential for HTTPOnly cookies
});

const userData = await fetch('/wp-json/proxy/v1/api/wp/v2/users/me', {
    credentials: 'include'
});

// External APIs (if enabled)
const githubData = await fetch('/wp-json/proxy/v1/api/api.github.com/user', {
    credentials: 'include'
});
```

### 2. Session Management

#### Check Session Status
```javascript
const sessionCheck = await fetch('/wp-json/proxy/v1/session/validate', {
    credentials: 'include'
});

if (sessionCheck.ok) {
    const sessionInfo = await sessionCheck.json();
    console.log('Session valid until:', new Date(sessionInfo.data.expires_at * 1000));
}
```

#### Destroy Session (Logout)
```javascript
await fetch('/wp-json/proxy/v1/session/destroy', {
    method: 'POST',
    credentials: 'include'
});

console.log('Proxy session destroyed');
```

### 3. Error Handling

```javascript
async function makeProxiedRequest(endpoint) {
    try {
        const response = await fetch(`/wp-json/proxy/v1/api/${endpoint}`, {
            credentials: 'include'
        });

        if (response.status === 401) {
            // Session expired - need to re-authenticate
            console.log('Proxy session expired, redirecting to login...');
            window.location.href = '/login';
            return;
        }

        if (response.status === 403) {
            const error = await response.json();
            if (error.code === 'endpoint_not_proxied') {
                console.log('Endpoint not configured for proxy, using direct call...');
                // Fallback to direct API call
                return makeDirectRequest(endpoint);
            }
        }

        return await response.json();
    } catch (error) {
        console.error('Proxy request failed:', error);
        throw error;
    }
}
```

## 🌐 Deployment Scenarios

### Scenario 1: Same-Domain SPA
```
Frontend: https://mysite.com/app/
WordPress: https://mysite.com/
Proxy: Optional (security enhancement)
```

### Scenario 2: External Frontend (Recommended for Proxy)
```
Frontend: https://app.mysite.com/
WordPress: https://api.mysite.com/
Proxy: Highly Recommended 🔒
```

### Scenario 3: Static Hosting
```
Frontend: https://app.netlify.app/
WordPress: https://mywordpress.com/
Proxy: Maximum Security Required 🛡️
```

## 📊 Security Comparison

| Feature | Direct Mode | Proxy Mode |
|---------|-------------|------------|
| XSS Token Theft | ❌ Vulnerable | ✅ Protected |
| Token in JavaScript | ❌ Yes | ✅ Never |
| HTTPOnly Cookies | ❌ No | ✅ Yes |
| Client Secret Support | ❌ No | ✅ Yes |
| Backend Token Storage | ❌ No | ✅ Yes |
| CSRF Protection | ⚠️ Manual | ✅ Built-in |
| Complexity | ✅ Simple | ⚠️ Moderate |
| Performance | ✅ Fast | ⚠️ Slight overhead |

## 🔍 Monitoring & Debugging

### Enable Debug Logging
```php
// In wp-config.php or WordPress settings
define('WP_DEBUG_LOG', true);
```

### Check Logs
```bash
tail -f /path/to/wordpress/wp-content/debug.log | grep "API Proxy Debug"
```

### Common Log Messages
```
API Proxy Debug: Proxy request - {"path":"wp/v2/posts","method":"GET","session_id":"abc123"}
API Proxy Debug: Proxy response - {"path":"wp/v2/posts","status":200,"response_type":"json"}
API Proxy Debug: Session created for user - {"user_id":1,"auth_method":"oauth2"}
```

## ⚠️ Important Notes

### Cookie Requirements
- **SameSite=Strict**: Recommended for production
- **Secure=true**: Required for HTTPS sites
- **Path=/wp-json/proxy/v1/**: Scoped to proxy endpoints only

### Browser Compatibility
```javascript
// Check if credentials are supported
if ('credentials' in new Request('')) {
    console.log('Proxy mode supported ✅');
} else {
    console.log('Falling back to direct mode ⚠️');
}
```

### CORS Configuration
```php
// WordPress CORS settings should allow credentials
add_filter('wp_auth_multi_cors_headers', function($headers) {
    $headers['Access-Control-Allow-Credentials'] = 'true';
    return $headers;
});
```

## 🚀 Migration from Direct to Proxy Mode

### Step 1: Parallel Implementation
```javascript
class APIClient {
    constructor() {
        this.proxyMode = this.detectProxyMode();
    }

    async detectProxyMode() {
        try {
            const response = await fetch('/wp-json/proxy/v1/info');
            const info = await response.json();
            return info.data.proxy_enabled;
        } catch {
            return false;
        }
    }

    async makeRequest(endpoint, options = {}) {
        if (this.proxyMode) {
            return this.makeProxyRequest(endpoint, options);
        } else {
            return this.makeDirectRequest(endpoint, options);
        }
    }

    async makeProxyRequest(endpoint, options) {
        return fetch(`/wp-json/proxy/v1/api/${endpoint}`, {
            ...options,
            credentials: 'include'
        });
    }

    async makeDirectRequest(endpoint, options) {
        const token = localStorage.getItem('access_token');
        return fetch(`/wp-json/${endpoint}`, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            }
        });
    }
}
```

### Step 2: Gradual Migration
1. Enable proxy for user-sensitive endpoints only
2. Test thoroughly in staging environment
3. Monitor error logs for issues
4. Gradually enable more endpoint types
5. Eventually disable direct mode

### Step 3: Full Proxy Mode
```javascript
// Clean, simple proxy-only implementation
class SecureAPIClient {
    async request(endpoint, options = {}) {
        const response = await fetch(`/wp-json/proxy/v1/api/${endpoint}`, {
            ...options,
            credentials: 'include'
        });

        if (!response.ok) {
            throw new APIError(response.status, await response.json());
        }

        return response.json();
    }
}
```

## 📚 Additional Resources

- [OAuth2 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

**🔐 Remember**: The proxy mode trades some complexity for maximum security. It's especially recommended for production environments and external frontend applications.