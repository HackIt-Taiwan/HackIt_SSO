# SSO Session 一致性問題修復報告

## 問題描述

HackIt SSO 系統存在已登入用戶仍需重新登入的問題，特別是在 OIDC 授權流程中。用戶明明已經在系統中登入，但其他服務請求 SSO 授權時，系統仍會要求用戶重新進行 Magic Link 驗證。

## 根本原因分析

通過代碼審查發現以下問題：

### 1. 重複的 Session 檢查函數
- `app/routers/auth.py` 和 `app/routers/oidc.py` 中都有各自的 `check_user_session` 函數
- 兩個函數實作略有不同，可能造成不一致的行為
- 沒有統一的 session 檢查邏輯

### 2. Cookie 域名設定不一致
```python
# auth.py 中的設定
domain=".hackit.tw"

# oidc.py 中的設定
domain=f".{settings.SSO_DOMAIN}"  # 結果是 ".sso.hackit.tw"
```

這會導致：
- 跨子域名的 cookie 無法正確共享
- Session 在不同模組間無法被正確識別

### 3. 缺乏詳細的調試日誌
- OIDC 授權端點缺少足夠的 session 檢查日誌
- 難以追蹤 session 失效的原因

## 解決方案

### 1. 統一 Session 管理
將 session 檢查函數移到 `app/core/config.py`：

```python
async def check_user_session(request: Request) -> Optional[Dict[str, Any]]:
    """
    Centralized user session checking function.
    Check if user has an active SSO session via cookie.
    """
    try:
        session_cookie = request.cookies.get("hackit_sso_session")
        if not session_cookie:
            logger.debug("No SSO session cookie found")
            return None
        
        from app.core.database import redis_client
        session_data = redis_client.get(f"session:{session_cookie}")
        if not session_data:
            logger.debug(f"No session data found in Redis for cookie: {session_cookie[:8]}...")
            return None
        
        session_info = json.loads(session_data)
        
        current_time = int(time.time())
        expires_at = session_info.get("expires_at", 0)
        
        if expires_at < current_time:
            redis_client.delete(f"session:{session_cookie}")
            logger.info(f"Session expired and cleaned up: {session_cookie[:8]}...")
            return None
        
        logger.debug(f"Valid session found for user: {session_info.get('email')}")
        return session_info
        
    except Exception as e:
        logger.error(f"Error checking user session: {str(e)}")
        return None
```

### 2. 統一 Cookie 域名設定
新增統一的 cookie 域名函數：

```python
def get_cookie_domain() -> str:
    """Get the correct cookie domain for SSO sessions."""
    return ".hackit.tw"
```

### 3. 更新所有路由
- `auth.py`：移除重複函數，導入統一的 session 檢查
- `oidc.py`：移除重複函數，導入統一的 session 檢查
- 所有 cookie 設定都使用 `get_cookie_domain()`

### 4. 增強 OIDC 授權端點
```python
@router.get("/oidc/authorize")
async def authorization_endpoint(...):
    """OIDC Authorization Endpoint with enhanced session checking"""
    # 檢查用戶是否已認證
    user_session = await check_user_session(request)
    if user_session:
        user_id = user_session.get("user_id")
        if user_id:
            logger.info(f"User {user_session.get('email')} already authenticated via SSO session, generating OIDC auth code for seamless login")
            # 直接生成授權碼，無縫登入
        else:
            logger.warning(f"Session found but missing user_id: {user_session}")
    else:
        logger.debug(f"No valid SSO session found for OIDC authorization request from client {client_id}")
```

## 改進效果

### 1. 無縫 SSO 體驗
- 已登入用戶訪問任何 OIDC 應用都會自動授權
- 無需重複進行 Magic Link 驗證
- 跨子域名的 session 共享正常工作

### 2. 一致的 Session 管理
- 所有模組使用相同的 session 檢查邏輯
- Cookie 域名設定完全一致
- Session 過期和清理邏輯統一

### 3. 更好的可維護性
- 中央化的 session 管理函數
- 統一的配置管理
- 詳細的調試日誌

### 4. 強化的日誌記錄
- Session 檢查過程的詳細日誌
- OIDC 授權流程的追蹤信息
- 便於問題診斷和調試

## 測試建議

1. **基本 SSO 測試**：
   - 用戶登入 SSO 系統
   - 訪問 OIDC 應用（如 Outline）
   - 確認無需重新登入

2. **跨子域名測試**：
   - 在 `sso.hackit.tw` 登入
   - 訪問 `data.hackit.tw` 或其他子域名
   - 確認 session 正常共享

3. **Session 過期測試**：
   - 等待 session 過期
   - 確認過期後能正確要求重新登入

4. **多瀏覽器測試**：
   - 在不同瀏覽器中測試登入狀態
   - 確認 cookie 隔離正常工作

## 相關文件

- **修改的文件**：
  - `app/core/config.py`：新增統一的 session 管理函數
  - `app/routers/auth.py`：移除重複函數，使用統一配置
  - `app/routers/oidc.py`：移除重複函數，增強授權端點
  - `.cursorrules`：更新 Lessons 和 Scratchpad

- **相關文檔**：
  - `OIDC_INTEGRATION_GUIDE.md`：OIDC 集成指南
  - `API_DOCUMENTATION.md`：API 文檔
  - `README.md`：專案說明

## 結論

此次修復解決了 HackIt SSO 系統中 session 管理不一致的根本問題，確保：

1. **用戶體驗**：已登入用戶享受真正的無縫 SSO 體驗
2. **系統穩定性**：統一的 session 管理減少不一致性問題
3. **可維護性**：中央化的配置和函數便於未來維護
4. **可觀測性**：詳細的日誌記錄便於問題診斷

該修復符合現代 SSO 系統的最佳實踐，為用戶提供流暢一致的認證體驗。 