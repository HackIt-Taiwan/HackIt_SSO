# HackIt SSO - Centralized Authentication Service

A secure, scalable, and enterprise-grade Single Sign-On (SSO) service for the HackIt organization, featuring military-grade security and seamless cross-domain authentication.

## 🔐 Features

- **🆔 OpenID Connect (OIDC)**: Standards-compliant SSO for third-party applications (Outline, GitLab, etc.)
- **🔐 Magic Link Authentication**: Passwordless login via secure email links
- **🛡️ Military-Grade Security**: HMAC-SHA256 signature authentication
- **🌐 Cross-Domain SSO**: Unified authentication across all `hackit.tw` subdomains
- **⏱️ Rate Limiting**: Anti-abuse protection with intelligent throttling
- **📍 Real-time IP Tracking**: Security monitoring with login location display
- **🔑 JWT Token Management**: RS256 signed tokens with automatic key rotation
- **🤖 Cloudflare Turnstile**: Invisible CAPTCHA protection
- **📊 Database Service Integration**: Centralized user management via API

## 🏗️ Architecture

This SSO service has been completely refactored to use a **centralized database service** instead of direct MongoDB connections, providing:

- **Decoupled Architecture**: No direct database dependencies
- **Scalable Design**: Microservices-based approach
- **Consistent API**: RESTful interface for all data operations
- **Enhanced Security**: HMAC-authenticated database API calls
- **Easy Maintenance**: Centralized data management

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Redis Server
- Access to HackIt Database Service
- SMTP Email Service (Gmail recommended)
- Cloudflare Turnstile account

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository_url>
   cd HackIt_SSO
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the service**
   ```bash
   python start.py
   ```

The SSO service will be available at `http://localhost:8000`

## ⚙️ Configuration

### Environment Variables

#### Database Service (Required)
```bash
DATABASE_SERVICE_URL=http://localhost:8001
DATABASE_SERVICE_SECRET=your_secret_key
```

#### Redis Configuration
```bash
REDIS_URL=redis://localhost:6379/0
# Or with password:
# REDIS_URL=redis://username:password@localhost:6379/0
```

#### JWT Settings
```bash
SECRET_KEY=your_jwt_secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
MAGIC_LINK_TOKEN_EXPIRE_MINUTES=15
```

#### Email Configuration
```bash
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_FROM=your_email@gmail.com
MAIL_PORT=465
MAIL_SERVER=smtp.gmail.com
MAIL_SSL_TLS=true
```

#### Cloudflare Turnstile
```bash
TURNSTILE_SITE_KEY=your_site_key
TURNSTILE_SECRET_KEY=your_secret_key
```

## 📡 API Endpoints

### Authentication Endpoints

- `GET /auth/` - Login page
- `POST /auth/magic-link` - Send magic link to email
- `GET /auth/verify` - Verify magic link token
- `GET /auth/status` - Check authentication status
- `POST /auth/logout` - Logout and clear session

### OIDC Endpoints

- `GET /.well-known/openid-configuration` - OIDC discovery document
- `GET /oidc/authorize` - Authorization endpoint
- `POST /oidc/token` - Token endpoint  
- `GET /oidc/userinfo` - User information endpoint
- `GET /oidc/jwks` - JSON Web Key Set
- `POST /oidc/register` - Client registration (development)

### SSO Endpoints

- `POST /auth/sso/verify` - Verify SSO token for cross-domain auth
- `GET /auth/sso/config` - Get SSO configuration
- `POST /auth/sso/refresh` - Refresh authentication token

### System Endpoints

- `GET /health` - Health check
- `GET /` - Service information

## 🔒 Security Features

### Magic Link Security
- **15-minute expiration**: Links automatically expire
- **Rate limiting**: Maximum 3 requests per 15 minutes
- **Token reuse**: Same token for repeated requests within window
- **IP tracking**: Login location monitoring
- **User validation**: Only existing users can receive magic links

### Cross-Domain Authentication
- **HMAC signature verification**: Prevents request tampering
- **Domain whitelist**: Restricted to authorized HackIt domains
- **Timestamp validation**: 5-minute replay attack prevention
- **JWT stateless tokens**: Secure user session management

### Database Security
- **API-only access**: No direct database connections
- **HMAC authentication**: All database requests signed
- **Encrypted communication**: HTTPS-only in production
- **Access logging**: Comprehensive audit trails

## 🧪 Development

### Running in Development Mode

```bash
# Start with auto-reload
uvicorn start:app --reload --host 0.0.0.0 --port 8000
```

### Testing Magic Link Flow

1. Access the login page: `http://localhost:8000/auth/`
2. Enter your email address
3. Complete Turnstile verification
4. Check your email for the magic link
5. Click the link to authenticate

### API Testing

Use the interactive API documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## 🔧 Integration Guide

### Frontend Integration

```javascript
// Check SSO status
async function checkSSO() {
    const token = localStorage.getItem('hackit_sso_token');
    if (!token) return null;
    
    const response = await fetch('/auth/sso/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token: token,
            domain: window.location.hostname
        })
    });
    
    return response.ok ? await response.json() : null;
}
```

### Backend Integration

```python
from app.crud.user_api import get_user_by_email, get_user_by_id

# Get user by email
user = await get_user_by_email("user@example.com")

# Get user by ID
user = await get_user_by_id("507f1f77bcf86cd799439011")
```

## 📊 Monitoring

### Health Checks

```bash
curl http://localhost:8000/health
```

### Logs

Application logs are written to `app.log` and include:
- Authentication attempts
- Magic link generation
- Error tracking
- Performance metrics

## 🛠️ Troubleshooting

### Common Issues

1. **Database Service Connection**
   - Verify `DATABASE_SERVICE_URL` is correct
   - Check `DATABASE_SERVICE_SECRET` matches
   - Ensure database service is running

2. **Email Delivery**
   - Verify SMTP settings
   - Check spam folder
   - Confirm app password for Gmail

3. **Redis Connection**
   - Verify Redis server is running
   - Check connection parameters
   - Test with `redis-cli`

4. **Turnstile Verification**
   - Verify site key configuration
   - Check domain whitelist
   - Test in different browsers

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For issues and questions:
- 📧 Email: tech@hackit.tw
- 🐛 Issues: Create a GitHub issue
- 📖 Docs: Check the API documentation

---

**Note**: This service requires the HackIt Database Service to be running. See the [Database Service Documentation](API_DOCUMENTATION.md) for setup instructions.
