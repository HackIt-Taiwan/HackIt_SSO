# Outline Wiki - HackIt SSO Integration

這個指南展示如何將 Outline Wiki 與 HackIt SSO 系統整合。

## 📋 前置需求

1. 已運行的 HackIt SSO 服務
2. Outline Wiki 實例
3. 管理員權限

## 🔧 步驟 1: 註冊 OIDC 客戶端

使用註冊工具：

```bash
cd /path/to/hackit-sso
python register_oidc_client.py
```

輸入以下資訊：
- **客戶端 ID**: `outline-wiki`
- **客戶端名稱**: `Outline Wiki`
- **重定向 URI**: `https://wiki.hackit.tw/auth/oidc.callback`

記錄生成的客戶端密鑰！

## 🔧 步驟 2: 配置 Outline

在 Outline 的 `.env` 檔案中添加：

```env
# OIDC Authentication
OIDC_CLIENT_ID=outline-wiki
OIDC_CLIENT_SECRET=你的客戶端密鑰
OIDC_AUTH_URI=https://sso.hackit.tw/oidc/authorize
OIDC_TOKEN_URI=https://sso.hackit.tw/oidc/token
OIDC_USERINFO_URI=https://sso.hackit.tw/oidc/userinfo
OIDC_USERNAME_CLAIM=preferred_username
OIDC_DISPLAY_NAME=HackIt SSO
OIDC_SCOPES=openid profile email
```

## 🔧 步驟 3: 重啟 Outline

```bash
docker-compose restart outline
```

## 🧪 測試流程

1. 訪問 `https://wiki.hackit.tw`
2. 點擊 "Login with HackIt SSO"
3. 系統會重定向到 HackIt SSO 登入頁面
4. 輸入你的 HackIt 電子郵件地址
5. 檢查郵件並點擊 Magic Link
6. 自動重定向回 Outline 並完成登入

## 🔍 疑難排解

### 問題：重定向 URI 不匹配

確保在 OIDC 客戶端註冊時使用的重定向 URI 與 Outline 配置中的完全一致。

### 問題：Token 驗證失敗

檢查：
- 客戶端 ID 和密鑰是否正確
- SSO 服務是否可訪問
- 時間同步是否正確

### 問題：用戶資訊不完整

確保 OIDC_SCOPES 包含 `profile email`，這樣才能獲取完整的用戶資訊。

## 📊 監控與日誌

查看 SSO 服務日誌：
```bash
docker logs hackit-sso
```

查看 Outline 日誌：
```bash
docker logs outline
```

## 🔒 安全建議

1. **HTTPS Only**: 確保所有通信都使用 HTTPS
2. **域名驗證**: 只允許授權的 hackit.tw 子域名
3. **定期輪換**: 定期更新客戶端密鑰
4. **監控登入**: 定期檢查異常登入活動

## 🎉 完成！

現在你的 Outline Wiki 已經與 HackIt SSO 完全整合。使用者可以使用他們的 HackIt 帳戶無縫登入 Wiki！ 