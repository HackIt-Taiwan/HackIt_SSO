#!/usr/bin/env python3
"""
OIDC Client Registration Tool for HackIt SSO

This script helps register OIDC clients like Outline or other applications
that need to integrate with the HackIt SSO system.
"""

import requests
import secrets
import json
import sys
from urllib.parse import urlparse

def generate_client_secret(length=32):
    """Generate a secure client secret."""
    return secrets.token_urlsafe(length)

def register_client(base_url, client_data, admin_key):
    """Register OIDC client with the SSO server."""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {admin_key}"
        }
        
        response = requests.post(
            f"{base_url}/oidc/register",
            json=client_data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"錯誤：無法註冊 OIDC 客戶端：{e}")
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 401:
                print("認證錯誤：需要提供有效的管理員金鑰")
            elif e.response.status_code == 403:
                print("權限錯誤：管理員金鑰無效")
        return None

def main():
    """Main registration process."""
    print("🔐 HackIt SSO - OIDC 客戶端註冊工具")
    print("=" * 50)
    
    # Get SSO server URL
    sso_url = input("SSO 伺服器 URL (預設: https://sso.hackit.tw): ").strip()
    if not sso_url:
        sso_url = "https://sso.hackit.tw"
    
    # Validate URL
    try:
        parsed = urlparse(sso_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("無效的 URL")
    except ValueError as e:
        print(f"錯誤：{e}")
        sys.exit(1)
    
    print(f"\n使用 SSO 伺服器：{sso_url}")
    
    # Get admin key
    print("\n🔑 管理員認證")
    admin_key = input("管理員金鑰 (OIDC_ADMIN_KEY): ").strip()
    if not admin_key:
        print("錯誤：管理員金鑰不能為空")
        sys.exit(1)
    
    # Get client information
    print("\n📝 客戶端資訊")
    client_id = input("客戶端 ID (例如: outline-wiki): ").strip()
    if not client_id:
        print("錯誤：客戶端 ID 不能為空")
        sys.exit(1)
    
    client_name = input("客戶端名稱 (例如: Outline Wiki): ").strip()
    if not client_name:
        client_name = client_id
    
    # Get redirect URIs
    print("\n🔗 重定向 URI 設定")
    redirect_uris = []
    while True:
        uri = input(f"重定向 URI #{len(redirect_uris) + 1} (空白結束): ").strip()
        if not uri:
            break
        try:
            parsed = urlparse(uri)
            if not parsed.scheme or not parsed.netloc:
                print("警告：無效的 URI 格式，請確認是否正確")
            redirect_uris.append(uri)
        except Exception:
            print("警告：URI 格式可能有問題")
            redirect_uris.append(uri)
    
    if not redirect_uris:
        print("錯誤：至少需要一個重定向 URI")
        sys.exit(1)
    
    # Generate client secret
    client_secret = generate_client_secret()
    
    # Create client data
    client_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "openid profile email",
        "token_endpoint_auth_method": "client_secret_basic"
    }
    
    # Show summary
    print("\n📋 客戶端註冊摘要")
    print("-" * 30)
    print(f"客戶端 ID: {client_id}")
    print(f"客戶端名稱: {client_name}")
    print(f"重定向 URI:")
    for uri in redirect_uris:
        print(f"  - {uri}")
    print(f"授權類型: authorization_code, refresh_token")
    print(f"回應類型: code")
    print(f"作用域: openid profile email")
    
    # Confirm registration
    confirm = input("\n確認註冊此客戶端？(y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print("註冊已取消")
        sys.exit(0)
    
    # Register client
    print("\n🚀 註冊客戶端中...")
    result = register_client(sso_url, client_data, admin_key)
    
    if result and result.get("message"):
        print("✅ 客戶端註冊成功！")
        print("\n🔑 客戶端憑證資訊")
        print("=" * 40)
        print(f"客戶端 ID: {client_id}")
        print(f"客戶端密鑰: {client_secret}")
        print("\n⚠️  請妥善保存客戶端密鑰，這是唯一顯示的機會！")
        
        # Show environment variable to add
        if result.get("env_variable"):
            print("\n🔧 環境變數配置 (Base64 編碼)")
            print("=" * 40)
            print("請將以下環境變數添加到您的 .env 文件中：")
            print()
            print(result.get("env_variable"))
            print()
            if result.get("json_preview"):
                print("📋 JSON 內容預覽：")
                print(result.get("json_preview"))
                print()
            print("⚠️  添加後請重啟 SSO 服務生效！")
            print("💡 使用 Base64 編碼避免 Coolify 環境變數解析問題")
        
        # Generate configuration for common applications
        print("\n📖 OIDC 配置資訊")
        print("-" * 30)
        print(f"發行者 (Issuer): {sso_url}")
        print(f"授權端點: {sso_url}/oidc/authorize")
        print(f"令牌端點: {sso_url}/oidc/token")
        print(f"用戶資訊端點: {sso_url}/oidc/userinfo")
        print(f"JWKS URI: {sso_url}/oidc/jwks")
        print(f"探索文檔: {sso_url}/.well-known/openid-configuration")
        
        # Outline specific configuration
        if "outline" in client_id.lower():
            print("\n📝 Outline Wiki 專用配置")
            print("-" * 30)
            print("在 Outline 的環境變數中設置：")
            print(f"OIDC_CLIENT_ID={client_id}")
            print(f"OIDC_CLIENT_SECRET={client_secret}")
            print(f"OIDC_AUTH_URI={sso_url}/oidc/authorize")
            print(f"OIDC_TOKEN_URI={sso_url}/oidc/token")
            print(f"OIDC_USERINFO_URI={sso_url}/oidc/userinfo")
            print(f"OIDC_LOGOUT_URI={sso_url}/oidc/endsession")
            print(f"OIDC_DISPLAY_NAME=HackIt SSO")
            print("OIDC_SCOPES=openid profile email")
        
        # Save to file
        config_file = f"{client_id}_oidc_config.json"
        config_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "issuer": sso_url,
            "authorization_endpoint": f"{sso_url}/oidc/authorize",
            "token_endpoint": f"{sso_url}/oidc/token",
            "userinfo_endpoint": f"{sso_url}/oidc/userinfo",
            "jwks_uri": f"{sso_url}/oidc/jwks",
            "discovery_endpoint": f"{sso_url}/.well-known/openid-configuration"
        }
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            print(f"\n💾 配置已保存到：{config_file}")
        except Exception as e:
            print(f"\n警告：無法保存配置文件：{e}")
        
    else:
        print("❌ 客戶端註冊失敗")
        if result:
            print(f"錯誤：{result}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n註冊已中斷")
        sys.exit(1)
    except Exception as e:
        print(f"\n錯誤：{e}")
        sys.exit(1) 