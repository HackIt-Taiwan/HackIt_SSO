/**
 * HackIt SSO JavaScript SDK
 * 
 * 提供軍用級別的統一認證服務，支援所有 HackIt 子域名
 * Version: 1.0.0
 * 
 * @author HackIt Tech Team
 * @license MIT
 */

class HackItSSO {
    constructor(options = {}) {
        this.baseURL = options.baseURL || 'https://sso.hackit.tw';
        this.tokenKey = options.tokenKey || 'hackit_sso_token';
        this.secretKey = options.secretKey || null;
        this.autoRefresh = options.autoRefresh !== false;
        this.refreshInterval = options.refreshInterval || 15 * 60 * 1000; // 15 minutes
        this.debug = options.debug || false;
        
        this.user = null;
        this.loading = false;
        this.refreshTimer = null;
        
        // 事件監聽器
        this.listeners = {
            login: [],
            logout: [],
            error: [],
            refresh: []
        };
        
        this.log('HackIt SSO SDK initialized');
    }
    
    /**
     * 初始化 SSO 檢查
     */
    async init() {
        this.loading = true;
        
        try {
            const token = this.getToken();
            if (token) {
                this.user = await this.verifyToken(token);
                if (this.user && this.autoRefresh) {
                    this.startAutoRefresh();
                }
            }
        } catch (error) {
            this.handleError('Initialization failed', error);
        } finally {
            this.loading = false;
        }
        
        return this.user;
    }
    
    /**
     * 驗證 SSO token
     */
    async verifyToken(token, useSignature = false) {
        try {
            const domain = window.location.hostname;
            const payload = {
                token: token,
                domain: domain
            };
            
            // 如果提供了 secretKey，使用簽名驗證
            if (useSignature && this.secretKey) {
                const timestamp = Math.floor(Date.now() / 1000);
                const signature = await this.createSignature(token, timestamp, domain);
                
                payload.timestamp = timestamp;
                payload.signature = signature;
            }
            
            const response = await fetch(`${this.baseURL}/auth/sso/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Token verification failed');
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.log('Token verified successfully', data.user);
                return data.user;
            } else {
                this.removeToken();
                return null;
            }
            
        } catch (error) {
            this.handleError('Token verification failed', error);
            this.removeToken();
            return null;
        }
    }
    
    /**
     * 創建 HMAC 簽名
     */
    async createSignature(token, timestamp, domain) {
        if (!this.secretKey) {
            throw new Error('Secret key required for signature creation');
        }
        
        try {
            const message = `${token}:${timestamp}:${domain}`;
            const encoder = new TextEncoder();
            
            const key = await crypto.subtle.importKey(
                'raw',
                encoder.encode(this.secretKey),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            
            const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
            
            return Array.from(new Uint8Array(signature))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
                
        } catch (error) {
            this.handleError('Signature creation failed', error);
            throw error;
        }
    }
    
    /**
     * 獲取 SSO 配置
     */
    async getConfig() {
        try {
            const domain = window.location.hostname;
            const response = await fetch(`${this.baseURL}/auth/sso/config?domain=${encodeURIComponent(domain)}`);
            
            if (!response.ok) {
                throw new Error('Failed to fetch SSO config');
            }
            
            return await response.json();
            
        } catch (error) {
            this.handleError('Config fetch failed', error);
            return null;
        }
    }
    
    /**
     * 刷新 token
     */
    async refreshToken() {
        try {
            const token = this.getToken();
            if (!token) {
                throw new Error('No token to refresh');
            }
            
            const response = await fetch(`${this.baseURL}/auth/sso/refresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Token refresh failed');
            }
            
            const data = await response.json();
            this.setToken(data.access_token);
            
            this.log('Token refreshed successfully');
            this.emit('refresh', data);
            
            return data.access_token;
            
        } catch (error) {
            this.handleError('Token refresh failed', error);
            this.logout();
            throw error;
        }
    }
    
    /**
     * 登入（跳轉到 SSO 頁面）
     */
    login(returnUrl = null) {
        const currentUrl = returnUrl || window.location.href;
        const loginUrl = new URL(`${this.baseURL}/auth/`);
        loginUrl.searchParams.set('return_url', currentUrl);
        
        this.log('Redirecting to login page');
        window.location.href = loginUrl.toString();
    }
    
    /**
     * 登出
     */
    logout() {
        this.stopAutoRefresh();
        this.removeToken();
        this.user = null;
        
        this.log('User logged out');
        this.emit('logout');
    }
    
    /**
     * 開始自動刷新 token
     */
    startAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
        
        this.refreshTimer = setInterval(() => {
            this.refreshToken().catch(error => {
                this.log('Auto refresh failed', error);
            });
        }, this.refreshInterval);
        
        this.log('Auto refresh started');
    }
    
    /**
     * 停止自動刷新
     */
    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
            this.log('Auto refresh stopped');
        }
    }
    
    /**
     * 檢查用戶是否已登入
     */
    isAuthenticated() {
        return this.user !== null;
    }
    
    /**
     * 獲取當前用戶資訊
     */
    getUser() {
        return this.user;
    }
    
    /**
     * 獲取用戶頭像 URL
     */
    getUserAvatarUrl() {
        return this.user ? this.user.avatar_url : null;
    }
    
    /**
     * 獲取 token
     */
    getToken() {
        try {
            return localStorage.getItem(this.tokenKey);
        } catch (error) {
            this.log('Failed to get token from localStorage', error);
            return null;
        }
    }
    
    /**
     * 設置 token
     */
    setToken(token) {
        try {
            localStorage.setItem(this.tokenKey, token);
            this.log('Token saved to localStorage');
        } catch (error) {
            this.handleError('Failed to save token', error);
        }
    }
    
    /**
     * 移除 token
     */
    removeToken() {
        try {
            localStorage.removeItem(this.tokenKey);
            this.log('Token removed from localStorage');
        } catch (error) {
            this.log('Failed to remove token from localStorage', error);
        }
    }
    
    /**
     * 添加事件監聽器
     */
    on(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event].push(callback);
        }
    }
    
    /**
     * 移除事件監聽器
     */
    off(event, callback) {
        if (this.listeners[event]) {
            const index = this.listeners[event].indexOf(callback);
            if (index > -1) {
                this.listeners[event].splice(index, 1);
            }
        }
    }
    
    /**
     * 觸發事件
     */
    emit(event, data = null) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    this.log('Event callback error', error);
                }
            });
        }
    }
    
    /**
     * 錯誤處理
     */
    handleError(message, error) {
        this.log(message, error);
        this.emit('error', { message, error });
    }
    
    /**
     * 日誌輸出
     */
    log(message, data = null) {
        if (this.debug) {
            console.log(`[HackIt SSO] ${message}`, data || '');
        }
    }
    
    /**
     * 安全的 API 調用（自動處理 token）
     */
    async secureApiCall(url, options = {}) {
        const token = this.getToken();
        if (!token) {
            throw new Error('No authentication token available');
        }
        
        const headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        const response = await fetch(url, {
            ...options,
            headers
        });
        
        if (response.status === 401) {
            // Token 可能過期，嘗試刷新
            try {
                await this.refreshToken();
                // 重試原始請求
                const retryHeaders = {
                    'Authorization': `Bearer ${this.getToken()}`,
                    'Content-Type': 'application/json',
                    ...options.headers
                };
                
                return fetch(url, {
                    ...options,
                    headers: retryHeaders
                });
                
            } catch (refreshError) {
                // 刷新失敗，需要重新登入
                this.logout();
                throw new Error('Authentication required');
            }
        }
        
        return response;
    }
}

// React Hook (如果在 React 環境中)
if (typeof React !== 'undefined') {
    const { useState, useEffect } = React;
    
    function useHackItSSO(options = {}) {
        const [sso] = useState(() => new HackItSSO(options));
        const [user, setUser] = useState(null);
        const [loading, setLoading] = useState(true);
        
        useEffect(() => {
            // 設置事件監聽器
            const handleLogin = (userData) => setUser(userData);
            const handleLogout = () => setUser(null);
            
            sso.on('login', handleLogin);
            sso.on('logout', handleLogout);
            
            // 初始化
            sso.init().then(userData => {
                setUser(userData);
                setLoading(false);
            });
            
            return () => {
                sso.off('login', handleLogin);
                sso.off('logout', handleLogout);
                sso.stopAutoRefresh();
            };
        }, [sso]);
        
        return {
            user,
            loading,
            isAuthenticated: sso.isAuthenticated(),
            login: (returnUrl) => sso.login(returnUrl),
            logout: () => sso.logout(),
            sso
        };
    }
    
    window.useHackItSSO = useHackItSSO;
}

// Vue.js Composable (如果在 Vue 環境中)
if (typeof Vue !== 'undefined') {
    const { ref, onMounted, onUnmounted } = Vue;
    
    function useHackItSSO(options = {}) {
        const sso = new HackItSSO(options);
        const user = ref(null);
        const loading = ref(true);
        
        const handleLogin = (userData) => { user.value = userData; };
        const handleLogout = () => { user.value = null; };
        
        onMounted(async () => {
            sso.on('login', handleLogin);
            sso.on('logout', handleLogout);
            
            const userData = await sso.init();
            user.value = userData;
            loading.value = false;
        });
        
        onUnmounted(() => {
            sso.off('login', handleLogin);
            sso.off('logout', handleLogout);
            sso.stopAutoRefresh();
        });
        
        return {
            user,
            loading,
            isAuthenticated: () => sso.isAuthenticated(),
            login: (returnUrl) => sso.login(returnUrl),
            logout: () => sso.logout(),
            sso
        };
    }
    
    window.useHackItSSO = useHackItSSO;
}

// 全域暴露
window.HackItSSO = HackItSSO;

// CommonJS 支援
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HackItSSO;
}

// AMD 支援
if (typeof define === 'function' && define.amd) {
    define([], function() {
        return HackItSSO;
    });
} 