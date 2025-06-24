# HackIt SSO - Coolify 部署指南

## 🚀 快速部署

### 1. 在 Coolify 中創建新專案

1. 登入您的 Coolify 管理後台
2. 點擊 "New Resource" → "Docker Compose"
3. 選擇 "Git Repository"

### 2. 配置 Git Repository

```
Repository URL: https://github.com/your-org/HackIt_SSO.git
Branch: main
Base Directory: /
```

### 3. 環境變數配置

在 Coolify 的 Environment Variables 頁面設置以下變數：

#### 🔐 必填變數

```bash
# Database Service API (中央化資料庫服務)
DATABASE_SERVICE_URL=https://db-api.hackit.tw
DATABASE_SERVICE_SECRET=your-secure-database-service-secret

# JWT 安全設定 (請使用強密碼，至少32字元)
SECRET_KEY=your-super-secure-secret-key-minimum-32-characters

# Redis 連線設定 (單一 URL 格式)
REDIS_URL=redis://username:password@redis-host:6379/0
```

#### ⚙️ 可選變數 (有預設值)

```bash
# Email 設定 (Magic Link 認證功能)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_FROM=noreply@hackit.tw
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_FROM_NAME=HackIt SSO
MAIL_STARTTLS=true
MAIL_SSL_TLS=false
USE_CREDENTIALS=true
VALIDATE_CERTS=true

# Cloudflare Turnstile 機器人防護
TURNSTILE_SECRET_KEY=your-turnstile-secret
TURNSTILE_SITE_KEY=your-turnstile-site-key

# JWT 設定
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
MAGIC_LINK_TOKEN_EXPIRE_MINUTES=15

# 域名與安全設定
SSO_DOMAIN=sso.hackit.tw
ALLOWED_DOMAINS=hackit.tw,*.hackit.tw

# OIDC 設定
OIDC_ISSUER=https://sso.hackit.tw
OIDC_KEY_ID=hackit-sso-key-1

# 環境設定
ENVIRONMENT=production
```

### 4. 域名設定

在 Coolify 的 Domains 頁面：

1. 添加您的域名：`sso.hackit.tw`
2. 啟用 SSL/TLS
3. 配置 DNS 指向您的伺服器

### 5. 部署

1. 點擊 "Deploy" 按鈕
2. 等待容器構建和啟動
3. 檢查日誌確認無錯誤

## 🧪 部署後測試

### 驗證服務狀態

```bash
curl https://sso.hackit.tw/health
```

期望回應：
```json
{
  "status": "healthy",
  "service": "HackIt SSO",
  "version": "2.0.0"
}
```

### 驗證 OIDC 發現端點

```bash
curl https://sso.hackit.tw/.well-known/openid-configuration
```

期望回應：
```json
{
  "issuer": "https://sso.hackit.tw",
  "authorization_endpoint": "https://sso.hackit.tw/oidc/authorize",
  "token_endpoint": "https://sso.hackit.tw/oidc/token",
  "userinfo_endpoint": "https://sso.hackit.tw/oidc/userinfo",
  "jwks_uri": "https://sso.hackit.tw/oidc/jwks"
}
```

### 測試登入頁面

訪問：`https://sso.hackit.tw/auth/`

應該看到 HackIt SSO 登入界面。

## 🔧 故障排除

### 常見問題

1. **容器啟動失敗 - Database Service 連線**
   ```bash
   # 檢查 DATABASE_SERVICE_URL 是否可達
   curl https://db-api.hackit.tw/health
   
   # 確認 DATABASE_SERVICE_SECRET 正確
   ```

2. **Redis 連接失敗**
   ```bash
   # 檢查 REDIS_URL 格式正確
   REDIS_URL=redis://username:password@redis-host:6379/0
   # 或無密碼版本
   REDIS_URL=redis://redis-host:6379/0
   ```

3. **Email 發送失敗**
   ```bash
   # Gmail SMTP 設定範例
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_STARTTLS=true
   MAIL_SSL_TLS=false
   ```

4. **JWT 簽名錯誤**
   ```bash
   # 確保 SECRET_KEY 至少32字元
   SECRET_KEY=your-super-secure-secret-key-minimum-32-characters
   ```

### 查看日誌

在 Coolify 管理後台：
1. 進入專案頁面
2. 點擊 "Logs" 標籤
3. 查看實時日誌輸出

常見日誌訊息：
```
✅ Database Service connected successfully
✅ Redis connected successfully
✅ FastAPI server started on port 7411
```

## 🔄 更新部署

1. 推送新代碼到 GitHub
2. 在 Coolify 中點擊 "Redeploy"
3. 等待重新構建完成

## 📚 相關文檔

- [SSO API 文檔](./SSO_API_DOCS.md)
- [OIDC 整合指南](./OIDC_INTEGRATION_GUIDE.md)
- [JavaScript SDK](./hackit-sso-sdk.js)

## 🏗️ 架構說明

新版本的 HackIt SSO 採用微服務架構：

```
┌─────────────────┐    API     ┌─────────────────┐
│   HackIt SSO    │◄──────────►│ Database Service│
│   (Auth & OIDC) │            │    (Centralized)│
└─────────────────┘            └─────────────────┘
        │                              │
        ▼                              ▼
┌─────────────────┐            ┌─────────────────┐
│      Redis      │            │     MongoDB     │
│   (Sessions)    │            │   (User Data)   │
└─────────────────┘            └─────────────────┘
```

優勢：
- ✅ 解除資料庫耦合，多服務共享使用者資料
- ✅ 集中管理使用者資料，統一 CRUD 操作
- ✅ 提高系統安全性與可維護性
- ✅ 支援橫向擴展與負載均衡

## 🎉 部署完成

恭喜！您的 HackIt SSO 服務現在已經在 Coolify 上運行了。

新版本支援：
- 🔐 Magic Link 無密碼登入
- 🌐 企業級 OIDC SSO 服務  
- 🤖 Cloudflare Turnstile 機器人防護
- 📧 郵件通知系統
- 🔄 跨域認證與 JWT 刷新 