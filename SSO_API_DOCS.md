# HackIt SSO API Documentation

## 🔐 Overview

HackIt SSO provides military-grade unified authentication services, supporting secure login and user status detection across all `hackit.tw` subdomains.

### 🛡️ Security Features

- **Military-Grade Encryption**: HMAC-SHA256 signature verification
- **Cross-Domain Security**: Strict domain whitelist mechanism
- **Privacy Protection**: Minimal user data exposure
- **Replay Attack Prevention**: Timestamp validation mechanism
- **JWT**: Stateless token verification
- **Centralized Database**: API-based user management with no direct database dependencies

---

## 🚀 Quick Start

### 1. Basic Integration

```javascript
// Basic SSO status check
async function checkSSOStatus() {
    const token = localStorage.getItem('hackit_sso_token');
    if (!token) return null;
    
    const response = await fetch('https://sso.hackit.tw/auth/sso/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            token: token,
            domain: window.location.hostname
        })
    });
    
    if (response.ok) {
        const data = await response.json();
        return data.success ? data.user : null;
    }
    
    return null;
}
```

### 2. Advanced Integration (with Signature Verification)

```javascript
// Generate HMAC signature
async function createSignature(token, timestamp, domain, secretKey) {
    const message = `${token}:${timestamp}:${domain}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Secure SSO verification
async function secureSSOCheck(token, secretKey) {
    const timestamp = Math.floor(Date.now() / 1000);
    const domain = window.location.hostname;
    const signature = await createSignature(token, timestamp, domain, secretKey);
    
    const response = await fetch('https://sso.hackit.tw/auth/sso/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            token: token,
            domain: domain,
            timestamp: timestamp,
            signature: signature
        })
    });
    
    return response.json();
}
```

---

## 📚 API Endpoints

### 🔍 POST /auth/sso/verify

Verify SSO token and retrieve user information

#### Request Body

```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "domain": "admin.hackit.tw",
    "timestamp": 1640995200,
    "signature": "a1b2c3d4e5f6..."
}
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | ✅ | JWT access token |
| `domain` | string | ✅ | Requesting domain |
| `timestamp` | integer | ⚡ | Unix timestamp (required for signature verification) |
| `signature` | string | ⚡ | HMAC-SHA256 signature (required for high security level) |

#### Response

**Success (200)**
```json
{
    "success": true,
    "user": {
        "user_id": "507f1f77bcf86cd799439011",
        "email": "user@hackit.tw",
        "real_name": "John Doe",
        "guild_id": 12345,
        "avatar_base64": "iVBORw0KGgoAAAANSUhEUgAA...",
        "education_stage": "university",
        "source": "discord",
        "bio": "Software developer",
        "location": "Taipei, Taiwan",
        "website": "https://johndoe.dev",
        "github_username": "johndoe",
        "registered_at": "2024-01-15T08:30:00.000Z"
    },
    "message": "Token verified successfully",
    "expires_at": 1641081600
}
```

**Error (401/403)**
```json
{
    "success": false,
    "user": null,
    "message": "Invalid token",
    "expires_at": null
}
```

#### Error Codes

| Code | Description |
|------|-------------|
| `401` | Token invalid or expired |
| `403` | Domain not authorized |
| `400` | Request format error |
| `500` | Internal server error |

---

### ⚙️ GET /auth/sso/config

Get SSO integration configuration

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | ✅ | Domain requesting configuration |

#### Example Request

```
GET /auth/sso/config?domain=admin.hackit.tw
```

#### Response

```json
{
    "sso_endpoint": "/auth/sso/verify",
    "login_url": "/auth/",
    "logout_url": "/auth/logout",
    "token_header": "Authorization",
    "token_prefix": "Bearer",
    "signature_required": true,
    "max_age": 1800,
    "algorithm": "HMAC-SHA256",
    "supported_domains": [
        "hackit.tw",
        "*.hackit.tw",
        "admin.hackit.tw",
        "dashboard.hackit.tw"
    ]
}
```

---

### 🔄 POST /auth/sso/refresh

Refresh SSO token

#### Headers

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 1800,
    "user_info": {
        "id": "507f1f77bcf86cd799439011",
        "email": "user@hackit.tw",
        "real_name": "John Doe"
    }
}
```

---

### 📧 POST /auth/send-magic-link

Send magic link to user email (for initial authentication)

#### Request Body

```json
{
    "email": "user@hackit.tw",
    "turnstile_token": "0.AQAAAAAAAAAAAAA..."
}
```

#### Response

```json
{
    "success": true,
    "message": "Magic link sent to your email. Please check your inbox (including spam folder)."
}
```

---

### ✅ GET /auth/status

Check current authentication status

#### Headers

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response

```json
{
    "authenticated": true,
    "user": {
        "id": "507f1f77bcf86cd799439011",
        "email": "user@hackit.tw",
        "real_name": "John Doe",
        "avatar_base64": "iVBORw0KGgoAAAANSUhEUgAA...",
        "last_login": "2024-01-15T09:45:00.000Z"
    },
    "expires_at": 1641081600
}
```

---

### 🚪 POST /auth/logout

Logout and invalidate session

#### Headers

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response

```json
{
    "success": true,
    "message": "Logged out successfully"
}
```

---

## 🏗️ Client Implementation Examples

### React Hook

```javascript
import { useState, useEffect, useCallback } from 'react';

export function useHackItSSO() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    
    const checkAuth = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            
            const token = localStorage.getItem('hackit_sso_token');
            if (!token) {
                setLoading(false);
                return;
            }
            
            const response = await fetch('/auth/status', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.authenticated) {
                    setUser(data.user);
                } else {
                    localStorage.removeItem('hackit_sso_token');
                    setUser(null);
                }
            } else {
                localStorage.removeItem('hackit_sso_token');
                setUser(null);
            }
        } catch (err) {
            setError(err.message);
            localStorage.removeItem('hackit_sso_token');
            setUser(null);
        } finally {
            setLoading(false);
        }
    }, []);
    
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);
    
    const login = useCallback(() => {
        window.location.href = 'https://sso.hackit.tw/auth/';
    }, []);
    
    const logout = useCallback(async () => {
        try {
            const token = localStorage.getItem('hackit_sso_token');
            if (token) {
                await fetch('/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            }
        } catch (err) {
            console.error('Logout error:', err);
        } finally {
            localStorage.removeItem('hackit_sso_token');
            setUser(null);
        }
    }, []);
    
    const refreshToken = useCallback(async () => {
        try {
            const token = localStorage.getItem('hackit_sso_token');
            if (!token) return false;
            
            const response = await fetch('/auth/sso/refresh', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('hackit_sso_token', data.access_token);
                return true;
            }
            
            return false;
        } catch (err) {
            console.error('Token refresh error:', err);
            return false;
        }
    }, []);
    
    return { 
        user, 
        loading, 
        error, 
        login, 
        logout, 
        refreshToken, 
        checkAuth 
    };
}

// Usage in component
function App() {
    const { user, loading, login, logout } = useHackItSSO();
    
    if (loading) return <div>Loading...</div>;
    
    return (
        <div>
            {user ? (
                <div>
                    <p>Welcome, {user.real_name}!</p>
                    <button onClick={logout}>Logout</button>
                </div>
            ) : (
                <button onClick={login}>Login</button>
            )}
        </div>
    );
}
```

### Vue.js Composable

```javascript
import { ref, onMounted, computed } from 'vue';

export function useHackItSSO() {
    const user = ref(null);
    const loading = ref(true);
    const error = ref(null);
    
    const isAuthenticated = computed(() => !!user.value);
    
    const checkAuth = async () => {
        try {
            loading.value = true;
            error.value = null;
            
            const token = localStorage.getItem('hackit_sso_token');
            if (!token) {
                loading.value = false;
                return;
            }
            
            const response = await fetch('/auth/status', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.authenticated) {
                    user.value = data.user;
                } else {
                    localStorage.removeItem('hackit_sso_token');
                    user.value = null;
                }
            } else {
                localStorage.removeItem('hackit_sso_token');
                user.value = null;
            }
        } catch (err) {
            error.value = err.message;
            localStorage.removeItem('hackit_sso_token');
            user.value = null;
        } finally {
            loading.value = false;
        }
    };
    
    const login = () => {
        window.location.href = 'https://sso.hackit.tw/auth/';
    };
    
    const logout = async () => {
        try {
            const token = localStorage.getItem('hackit_sso_token');
            if (token) {
                await fetch('/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            }
        } catch (err) {
            console.error('Logout error:', err);
        } finally {
            localStorage.removeItem('hackit_sso_token');
            user.value = null;
        }
    };
    
    onMounted(checkAuth);
    
    return {
        user: readonly(user),
        loading: readonly(loading),
        error: readonly(error),
        isAuthenticated,
        login,
        logout,
        checkAuth
    };
}
```

### Vanilla JavaScript Class

```javascript
class HackItSSO {
    constructor(options = {}) {
        this.baseURL = options.baseURL || 'https://sso.hackit.tw';
        this.tokenKey = options.tokenKey || 'hackit_sso_token';
        this.user = null;
        this.listeners = [];
    }
    
    // Event listener management
    addEventListener(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }
    
    removeEventListener(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
        }
    }
    
    emit(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => callback(data));
        }
    }
    
    // Authentication methods
    async init() {
        const token = localStorage.getItem(this.tokenKey);
        if (token) {
            this.user = await this.verifyToken(token);
            if (this.user) {
                this.emit('login', this.user);
            }
        }
        return this.user;
    }
    
    async verifyToken(token) {
        try {
            const response = await fetch(`${this.baseURL}/auth/status`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                return data.authenticated ? data.user : null;
            }
            
            return null;
        } catch (error) {
            console.error('Token verification failed:', error);
            this.logout();
            return null;
        }
    }
    
    login() {
        window.location.href = `${this.baseURL}/auth/`;
    }
    
    async logout() {
        try {
            const token = localStorage.getItem(this.tokenKey);
            if (token) {
                await fetch(`${this.baseURL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            localStorage.removeItem(this.tokenKey);
            this.user = null;
            this.emit('logout');
        }
    }
    
    async refreshToken() {
        try {
            const token = localStorage.getItem(this.tokenKey);
            if (!token) return false;
            
            const response = await fetch(`${this.baseURL}/auth/sso/refresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                localStorage.setItem(this.tokenKey, data.access_token);
                this.user = data.user_info;
                this.emit('tokenRefresh', this.user);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Token refresh failed:', error);
            return false;
        }
    }
    
    // Utility methods
    isAuthenticated() {
        return !!this.user;
    }
    
    getUser() {
        return this.user;
    }
    
    getToken() {
        return localStorage.getItem(this.tokenKey);
    }
}

// Usage example
const sso = new HackItSSO();

// Event listeners
sso.addEventListener('login', (user) => {
    console.log('User logged in:', user);
    updateUI(user);
});

sso.addEventListener('logout', () => {
    console.log('User logged out');
    updateUI(null);
});

// Initialize
sso.init().then(user => {
    if (user) {
        console.log('Already authenticated:', user);
    }
});

// Auto-refresh token every 15 minutes
setInterval(() => {
    if (sso.isAuthenticated()) {
        sso.refreshToken();
    }
}, 15 * 60 * 1000);
```

---

## 🔒 Security Best Practices

### 1. Token Management

```javascript
// ✅ Good practice
localStorage.setItem('hackit_sso_token', token);

// ❌ Avoid
document.cookie = `token=${token}`; // Vulnerable to XSS attacks
```

### 2. Automatic Token Refresh

```javascript
// Automatic refresh mechanism
class TokenManager {
    constructor(refreshInterval = 15 * 60 * 1000) { // 15 minutes
        this.refreshInterval = refreshInterval;
        this.refreshTimer = null;
        this.startAutoRefresh();
    }
    
    startAutoRefresh() {
        this.refreshTimer = setInterval(async () => {
            const token = localStorage.getItem('hackit_sso_token');
            if (token) {
                try {
                    const response = await fetch('/auth/sso/refresh', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        localStorage.setItem('hackit_sso_token', data.access_token);
                    } else {
                        // Token refresh failed, redirect to login
                        this.handleAuthFailure();
                    }
                } catch (error) {
                    console.error('Token refresh failed:', error);
                    this.handleAuthFailure();
                }
            }
        }, this.refreshInterval);
    }
    
    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
    
    handleAuthFailure() {
        localStorage.removeItem('hackit_sso_token');
        window.location.href = 'https://sso.hackit.tw/auth/';
    }
}

const tokenManager = new TokenManager();
```

### 3. Secure API Calls

```javascript
async function secureApiCall(endpoint, options = {}) {
    const token = localStorage.getItem('hackit_sso_token');
    
    if (!token) {
        throw new Error('No authentication token');
    }
    
    const response = await fetch(endpoint, {
        ...options,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
        }
    });
    
    if (response.status === 401) {
        // Token expired, try to refresh
        const refreshed = await refreshToken();
        if (refreshed) {
            // Retry the original request
            return secureApiCall(endpoint, options);
        } else {
            // Refresh failed, redirect to login
            localStorage.removeItem('hackit_sso_token');
            window.location.href = 'https://sso.hackit.tw/auth/';
            return;
        }
    }
    
    if (!response.ok) {
        throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }
    
    return response.json();
}
```

### 4. Cross-Site Request Forgery (CSRF) Protection

```javascript
// Include CSRF token in requests when available
async function csrfProtectedRequest(endpoint, data) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    
    return fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
            'Authorization': `Bearer ${localStorage.getItem('hackit_sso_token')}`
        },
        body: JSON.stringify(data)
    });
}
```

---

## 🔧 Configuration

### Environment Variables

```bash
# SSO Service Configuration
DATABASE_SERVICE_URL=http://localhost:8001
DATABASE_SERVICE_SECRET=your_database_service_secret_key

REDIS_URL=redis://localhost:6379/0
# Or with password:
# REDIS_URL=redis://username:password@localhost:6379/0

# JWT Configuration
SECRET_KEY=your_super_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
MAGIC_LINK_TOKEN_EXPIRE_MINUTES=15

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=465
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_SSL_TLS=true

# Cloudflare Turnstile
TURNSTILE_SITE_KEY=your_turnstile_site_key
TURNSTILE_SECRET_KEY=your_turnstile_secret_key
```

### Allowed Domains

Default allowed domains:
- `hackit.tw`
- `*.hackit.tw`
- `admin.hackit.tw`
- `dashboard.hackit.tw`
- `localhost` (development only)
- `127.0.0.1` (development only)

---

## 📊 Monitoring & Health Check

### Health Check Endpoint

```
GET /health
```

Response:
```json
{
    "status": "healthy",
    "service": "HackIt SSO",
    "version": "1.0.0",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "database_service": {
        "status": "connected",
        "url": "http://localhost:8001"
    },
    "redis": {
        "status": "connected",
        "host": "localhost:6379"
    }
}
```

### Metrics Monitoring

The SSO service provides comprehensive logging including:
- **Authentication Attempts**: Success/failure rates
- **Magic Link Generation**: Delivery status and timing
- **Token Verification**: Cross-domain usage patterns
- **Error Tracking**: Detailed error logs with context
- **Performance Metrics**: Response times and throughput
- **Security Events**: Failed authentications and suspicious activity

### Log Format

```json
{
    "timestamp": "2024-01-15T10:30:00.000Z",
    "level": "INFO",
    "service": "hackit-sso",
    "event": "magic_link_sent",
    "user_email": "user@hackit.tw",
    "client_ip": "192.168.1.100",
    "domain": "admin.hackit.tw",
    "metadata": {
        "delivery_time_ms": 1250,
        "rate_limit_count": 1
    }
}
```

---

## 🚨 Troubleshooting

### Common Issues

1. **CORS Errors**
   - Ensure your domain is in the allowed list
   - Check request headers configuration
   - Verify protocol (HTTP vs HTTPS) matches

2. **Token Verification Failed**
   - Check if token has expired
   - Verify SECRET_KEY consistency
   - Ensure proper Authorization header format

3. **Signature Verification Failed**
   - Check timestamp is within 5-minute window
   - Verify signature algorithm is correct
   - Ensure message format matches specification

4. **Domain Not Authorized**
   - Contact administrator to add domain to whitelist
   - Verify domain format is correct
   - Check subdomain wildcard permissions

5. **Database Service Connection**
   - Verify DATABASE_SERVICE_URL is reachable
   - Check DATABASE_SERVICE_SECRET is correct
   - Ensure database service is running and healthy

6. **Email Delivery Issues**
   - Check SMTP configuration
   - Verify app password for Gmail
   - Monitor spam folder
   - Check rate limiting status

### Debug Mode

Enable detailed logging in development:

```bash
export LOG_LEVEL=DEBUG
python start.py
```

### Testing Tools

```bash
# Test health endpoint
curl -X GET https://sso.hackit.tw/health

# Test token verification
curl -X POST https://sso.hackit.tw/auth/sso/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"your_token","domain":"admin.hackit.tw"}'

# Test database service connection
curl -X GET https://sso.hackit.tw/auth/status \
  -H "Authorization: Bearer your_token"
```

---

## 📞 Support

For issues and questions:
- 📧 **Email**: tech@hackit.tw
- 🐛 **Issues**: Create a GitHub issue
- 📖 **Docs**: [Complete Documentation](API_DOCUMENTATION.md)
- 🔧 **Database Service**: [Database API Documentation](API_DOCUMENTATION.md)

---

## 🔄 Migration Guide

### From Direct MongoDB to Database API

If migrating from an older version that used direct MongoDB connections:

1. **Update Environment Variables**
   ```bash
   # Remove MongoDB direct connection
   # MONGODB_URI=mongodb://...
   
   # Add Database Service configuration
   DATABASE_SERVICE_URL=http://localhost:8001
   DATABASE_SERVICE_SECRET=your_secret_key
   ```

2. **Update Dependencies**
   ```bash
   pip uninstall mongoengine
   pip install httpx  # If not already installed
   ```

3. **Code Changes**
   ```python
   # Old: Direct MongoDB usage
   from app.models.user import RegisteredUser
   user = RegisteredUser.objects(email=email).first()
   
   # New: Database API usage
   from app.crud.user_api import get_user_by_email
   user = await get_user_by_email(email)
   ```

4. **Test Integration**
   - Verify database service is running
   - Test all authentication flows
   - Monitor logs for any errors

---

**⚠️ Important Notes:**
- This API is for internal HackIt organization use only
- Never share SECRET_KEY in public repositories
- Regularly monitor and update token usage
- Follow principle of least privilege for access control
- All production traffic must use HTTPS
- Database operations are now async and require proper await handling 