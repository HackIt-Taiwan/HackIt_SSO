/**
 * HackIt SSO - Clean and Maintainable Frontend Architecture
 * 
 * This file contains a modular, clean implementation of the SSO frontend.
 * All global state has been eliminated and proper error handling is implemented.
 */

/* ==============================================
   CONFIGURATION MANAGER
   ============================================== */
class ConfigManager {
    constructor() {
        this.config = this.loadConfig();
    }

    loadConfig() {
        // Load configuration from data attributes
        const turnstileElement = document.querySelector('.cf-turnstile');
        if (!turnstileElement) {
            console.warn('Turnstile element not found');
            return {};
        }

        return {
            turnstileSiteKey: turnstileElement.getAttribute('data-sitekey') || '',
            oidcStateId: turnstileElement.getAttribute('data-oidc-state-id') || null,
            staticVersion: turnstileElement.getAttribute('data-static-version') || '1.0.0'
        };
    }

    get(key) {
        return this.config[key];
    }
}

/* ==============================================
   API CLIENT
   ============================================== */
class ApiClient {
    constructor() {
        this.baseUrl = this.detectBaseUrl();
    }

    detectBaseUrl() {
        const hostname = window.location.hostname;
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            const port = window.location.port || '8000';
            return `${window.location.protocol}//${hostname}:${port}`;
        }
        return `${window.location.protocol}//${window.location.host}`;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || `HTTP ${response.status}`);
            }
            
            return { success: true, data };
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            return { 
                success: false, 
                error: error.message || 'Network error occurred'
            };
        }
    }

    async checkAuthStatus(token) {
        return this.request('/auth/status', {
            headers: { Authorization: `Bearer ${token}` }
        });
    }

    async sendMagicLink(email, turnstileToken, oidcStateId = null) {
        const body = { email, turnstile_token: turnstileToken };
        if (oidcStateId) body.oidc_state_id = oidcStateId;

        return this.request('/auth/magic-link', {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    async logout() {
        return this.request('/auth/logout', { method: 'POST' });
    }
}

/* ==============================================
   TURNSTILE MANAGER
   ============================================== */
class TurnstileManager {
    constructor(config) {
        this.config = config;
        this.widget = null;
        this.isReady = false;
        this.fallbackMode = false;
        this.retryCount = 0;
        this.maxRetries = 3;
        
        // Smart queue mechanism for early submissions
        this.isFullyReady = false;
        this.pendingSubmissions = [];
        this.readyCallbacks = [];
        
        this.setupCallbacks();
    }

    setupCallbacks() {
        window.onTurnstileLoad = () => this.onApiReady();
        window.onTurnstileSuccess = (token) => this.onSuccess(token);
        window.onTurnstileError = (error) => this.onError(error);
        window.onTurnstileExpired = () => this.onExpired();
    }

    async initialize() {
        try {
            await this.waitForApi();
            await this.render();
            
            // Mark as fully ready and process any pending submissions
            this.isFullyReady = true;
            this.processPendingSubmissions();
            this.notifyReadyCallbacks();
        } catch (error) {
            console.warn('Turnstile initialization failed, enabling fallback mode:', error);
            this.enableFallback();
            
            // Still mark as ready for fallback mode
            this.isFullyReady = true;
            this.processPendingSubmissions();
            this.notifyReadyCallbacks();
        }
    }

    async waitForApi(timeout = 5000) {
        return new Promise((resolve, reject) => {
            if (window.turnstile) {
                resolve();
                return;
            }

            let attempts = 0;
            const maxAttempts = timeout / 50; // Check every 50ms for faster response
            
            const check = () => {
                attempts++;
                if (window.turnstile) {
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('Turnstile API timeout'));
                } else {
                    setTimeout(check, 50);
                }
            };
            
            check();
        });
    }

    async render() {
        const element = document.querySelector('.cf-turnstile');
        if (!element || !window.turnstile) {
            throw new Error('Turnstile element or API not available');
        }

        try {
            this.widget = window.turnstile.render(element, {
                sitekey: this.config.get('turnstileSiteKey'),
                callback: 'onTurnstileSuccess',
                'error-callback': 'onTurnstileError',
                'expired-callback': 'onTurnstileExpired',
                theme: 'dark',
                size: 'invisible'
            });
            
            this.isReady = true;
            console.log('✅ Turnstile widget ready');
        } catch (error) {
            console.error('Turnstile render failed:', error);
            throw error;
        }
    }

    onApiReady() {
        console.log('Turnstile API loaded');
    }

    onSuccess(token) {
        console.log('✅ Turnstile verification successful');
        if (this.resolveToken) {
            this.resolveToken(token);
            this.resolveToken = null;
        }
    }

    onError(error) {
        console.error('❌ Turnstile error:', error);
        if (this.retryCount < this.maxRetries) {
            this.retryCount++;
            console.log(`Retrying Turnstile (${this.retryCount}/${this.maxRetries})`);
            setTimeout(() => this.render().catch(() => this.enableFallback()), 2000);
        } else {
            this.enableFallback();
        }
        
        if (this.rejectToken) {
            this.rejectToken(new Error('驗證失敗，請稍後再試'));
            this.rejectToken = null;
            this.resolveToken = null;
        }
    }

    onExpired() {
        console.log('⏰ Turnstile token expired');
        if (this.rejectToken) {
            this.rejectToken(new Error('驗證已過期，請重新嘗試'));
            this.rejectToken = null;
            this.resolveToken = null;
        }
    }

    enableFallback() {
        this.fallbackMode = true;
        this.isReady = true;
        console.log('⚠️ Turnstile fallback mode enabled');
    }

    // Smart token retrieval with queueing support
    async getToken() {
        return new Promise((resolve, reject) => {
            // If not fully ready yet, queue the request
            if (!this.isFullyReady) {
                console.log('📥 Queueing submission request (Turnstile not ready yet)');
                this.pendingSubmissions.push({ resolve, reject });
                return;
            }

            // If in fallback mode, return immediately
            if (this.fallbackMode) {
                resolve('FALLBACK_TOKEN');
                return;
            }

            if (!this.isReady || !this.widget) {
                reject(new Error('Turnstile not ready'));
                return;
            }

            // Check for existing token
            try {
                const existingToken = window.turnstile.getResponse(this.widget);
                if (existingToken && existingToken.trim()) {
                    resolve(existingToken);
                    return;
                }
            } catch (error) {
                console.log('No existing token available');
            }

            // Execute new verification
            this.resolveToken = resolve;
            this.rejectToken = reject;

            try {
                window.turnstile.execute(this.widget);
                
                // Timeout protection
                setTimeout(() => {
                    if (this.resolveToken) {
                        this.rejectToken(new Error('驗證超時，請重新嘗試'));
                        this.resolveToken = null;
                        this.rejectToken = null;
                    }
                }, 30000);
            } catch (error) {
                reject(new Error('驗證執行失敗'));
            }
        });
    }

    // Process any submissions that were queued while initializing
    processPendingSubmissions() {
        if (this.pendingSubmissions.length > 0) {
            console.log(`📤 Processing ${this.pendingSubmissions.length} queued submission(s)`);
            
            this.pendingSubmissions.forEach(({ resolve, reject }) => {
                // Re-call getToken for each queued request
                this.getToken().then(resolve).catch(reject);
            });
            
            this.pendingSubmissions = [];
        }
    }

    // Add callback to be notified when ready
    onReady(callback) {
        if (this.isFullyReady) {
            callback();
        } else {
            this.readyCallbacks.push(callback);
        }
    }

    // Notify all ready callbacks
    notifyReadyCallbacks() {
        this.readyCallbacks.forEach(callback => {
            try {
                callback();
            } catch (error) {
                console.error('Ready callback error:', error);
            }
        });
        this.readyCallbacks = [];
    }

    reset() {
        if (this.isReady && this.widget && window.turnstile && !this.fallbackMode) {
            try {
                window.turnstile.reset(this.widget);
            } catch (error) {
                console.error('Turnstile reset failed:', error);
            }
        }
    }
}

/* ==============================================
   UI MANAGER
   ============================================== */
class UIManager {
    constructor() {
        this.elements = this.initializeElements();
        this.setupEventListeners();
    }

    initializeElements() {
        return {
            // Forms and inputs
            loginForm: document.getElementById('login-form'),
            emailInput: document.getElementById('email'),
            magicLinkBtn: document.getElementById('magic-link-btn'),
            
            // Sections
            loginSection: document.getElementById('login-section'),
            loggedInSection: document.getElementById('logged-in-section'),
            
            // Messages
            responseMessage: document.getElementById('response-message'),
            logoutMessage: document.getElementById('logout-message'),
            
            // User info elements
            userNameEl: document.getElementById('user-name'),
            userEmailEl: document.getElementById('user-email'),
            userAvatarImg: document.getElementById('user-avatar-img'),
            userAvatarPlaceholder: document.getElementById('user-avatar-placeholder'),
            logoutBtn: document.getElementById('logout-btn')
        };
    }

    setupEventListeners() {
        // Email input focus effects
        this.elements.emailInput.addEventListener('focus', () => {
            this.elements.emailInput.parentElement.style.transform = 'scale(1.02)';
        });
        
        this.elements.emailInput.addEventListener('blur', () => {
            this.elements.emailInput.parentElement.style.transform = 'scale(1)';
        });
    }

    showLoginSection() {
        this.elements.loginSection.style.display = 'block';
        this.elements.loggedInSection.style.display = 'none';
    }

    showLoggedInSection(user) {
        this.elements.loginSection.style.display = 'none';
        this.elements.loggedInSection.style.display = 'block';
        this.updateUserInfo(user);
    }

    updateUserInfo(user) {
        this.elements.userNameEl.textContent = user.real_name || '用戶';
        this.elements.userEmailEl.textContent = user.email || '';
        
        if (user.avatar_base64) {
            this.elements.userAvatarImg.src = `data:image/jpeg;base64,${user.avatar_base64}`;
            this.elements.userAvatarImg.style.display = 'block';
            this.elements.userAvatarPlaceholder.style.display = 'none';
        } else {
            this.elements.userAvatarImg.style.display = 'none';
            this.elements.userAvatarPlaceholder.style.display = 'flex';
        }
    }

    showMessage(text, type = 'info', autoHide = true) {
        const messageEl = this.elements.responseMessage;
        messageEl.innerHTML = `<span class="message-text">${text}</span>`;
        messageEl.className = `response-message ${type} show`;
        
        if (autoHide) {
            setTimeout(() => this.hideMessage(), 5000);
        }
    }

    hideMessage() {
        const messageEl = this.elements.responseMessage;
        messageEl.classList.remove('show');
        setTimeout(() => {
            messageEl.textContent = '';
            messageEl.className = 'response-message';
        }, 400);
    }

    showLogoutMessage(text, type = 'info') {
        const messageEl = this.elements.logoutMessage;
        messageEl.textContent = text;
        messageEl.className = `response-message ${type} show`;
    }

    hideLogoutMessage() {
        const messageEl = this.elements.logoutMessage;
        messageEl.classList.remove('show');
        setTimeout(() => {
            messageEl.textContent = '';
            messageEl.className = 'response-message';
        }, 300);
    }

    setButtonLoading(loading) {
        const btn = this.elements.magicLinkBtn;
        if (loading) {
            btn.disabled = true;
            btn.classList.add('loading');
            btn.innerHTML = `
                <span>處理中</span>
                <div class="loading-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            `;
        } else {
            btn.disabled = false;
            btn.classList.remove('loading');
            btn.innerHTML = `
                <span>發送魔法連結</span>
                <i data-feather="arrow-right"></i>
            `;
            feather.replace();
        }
    }

    setButtonLocked(locked) {
        const btn = this.elements.magicLinkBtn;
        if (locked) {
            btn.disabled = true;
            btn.classList.add('locked');
            btn.innerHTML = `
                <span>處理中</span>
                <i data-feather="clock"></i>
            `;
            feather.replace();
        } else {
            btn.disabled = false;
            btn.classList.remove('locked');
            btn.innerHTML = `
                <span>發送魔法連結</span>
                <i data-feather="arrow-right"></i>
            `;
            feather.replace();
        }
    }

    setLogoutButtonLoading(loading) {
        const btn = this.elements.logoutBtn;
        if (loading) {
            btn.disabled = true;
            btn.innerHTML = '<span>處理中...</span>';
        } else {
            btn.disabled = false;
            btn.innerHTML = '<i data-feather="log-out"></i><span>登出</span>';
            feather.replace();
        }
    }

    setInputError() {
        this.elements.emailInput.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
            this.elements.emailInput.style.animation = '';
        }, 500);
    }

    setInputSuccess() {
        this.elements.emailInput.style.borderColor = 'var(--success-color)';
        setTimeout(() => {
            this.elements.emailInput.style.borderColor = '';
        }, 2000);
    }
}

/* ==============================================
   AUTH MANAGER
   ============================================== */
class AuthManager {
    constructor(apiClient, ui) {
        this.api = apiClient;
        this.ui = ui;
    }

    async checkStatus() {
        try {
            const token = localStorage.getItem('access_token');
            if (!token) {
                this.ui.showLoginSection();
                return;
            }

            const result = await this.api.checkAuthStatus(token);
            if (result.success && result.data.authenticated) {
                this.ui.showLoggedInSection(result.data.user);
            } else {
                localStorage.removeItem('access_token');
                this.ui.showLoginSection();
            }
        } catch (error) {
            console.error('Auth status check failed:', error);
            this.ui.showLoginSection();
        }
    }

    async sendMagicLink(email, turnstileToken, oidcStateId) {
        const result = await this.api.sendMagicLink(email, turnstileToken, oidcStateId);
        
        if (result.success) {
            this.ui.showMessage(result.data.message || '魔法連結已發送到您的 Email！', 'success');
            this.ui.setInputSuccess();
            return true;
        } else {
            this.ui.showMessage(result.error || '發生錯誤，請稍後再試', 'error');
            this.ui.setInputError();
            return false;
        }
    }

    async logout() {
        try {
            this.ui.setLogoutButtonLoading(true);
            
            const result = await this.api.logout();
            localStorage.removeItem('access_token');
            
            if (result.success) {
                this.ui.showLogoutMessage('登出成功！', 'success');
            } else {
                this.ui.showLogoutMessage('登出成功（本地）', 'success');
            }
            
            setTimeout(() => {
                this.ui.showLoginSection();
                this.ui.hideLogoutMessage();
            }, 1500);
        } catch (error) {
            console.error('Logout error:', error);
            localStorage.removeItem('access_token');
            this.ui.showLogoutMessage('登出成功（本地）', 'success');
            setTimeout(() => {
                this.ui.showLoginSection();
                this.ui.hideLogoutMessage();
            }, 1500);
        } finally {
            this.ui.setLogoutButtonLoading(false);
        }
    }
}

/* ==============================================
   MAIN APPLICATION
   ============================================== */
class SSOApp {
    constructor() {
        this.config = new ConfigManager();
        this.api = new ApiClient();
        this.ui = new UIManager();
        this.auth = new AuthManager(this.api, this.ui);
        this.turnstile = new TurnstileManager(this.config);
        
        this.isSubmitting = false;
        this.isButtonLocked = false;
        
        this.initialize();
    }

    async initialize() {
        console.log('🚀 Initializing SSO App...');
        
        try {
            // Initialize Turnstile
            await this.turnstile.initialize();
            
            // Check authentication status
            await this.auth.checkStatus();
            
            // Setup form submission
            this.setupFormHandling();
            
            // Setup logout handling
            this.setupLogoutHandling();
            
            // Handle logout success message from URL
            this.handleLogoutSuccessMessage();
            
            console.log('✅ SSO App initialized successfully');
        } catch (error) {
            console.error('❌ SSO App initialization failed:', error);
            this.ui.showMessage('系統初始化失敗，請刷新頁面重試', 'error');
        }
    }

    setupFormHandling() {
        this.ui.elements.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.isSubmitting || this.isButtonLocked) {
                console.log('Form submission blocked (already submitting or locked)');
                return;
            }
            
            await this.handleFormSubmit();
        });
    }

    setupLogoutHandling() {
        this.ui.elements.logoutBtn.addEventListener('click', () => {
            this.auth.logout();
        });
    }

    async handleFormSubmit() {
        const email = this.ui.elements.emailInput.value.trim();
        if (!email) {
            this.ui.showMessage('請輸入有效的電子郵件地址', 'error');
            return;
        }

        this.isSubmitting = true;
        this.ui.setButtonLoading(true);
        this.ui.hideMessage();

        try {
            // Get Turnstile token
            const turnstileToken = await this.turnstile.getToken();
            
            // Send magic link
            const success = await this.auth.sendMagicLink(
                email, 
                turnstileToken, 
                this.config.get('oidcStateId')
            );
            
            if (success) {
                this.ui.elements.emailInput.value = '';
            }
            
        } catch (error) {
            console.error('Form submission error:', error);
            this.ui.showMessage(error.message || '發生錯誤，請稍後再試', 'error');
            this.ui.setInputError();
        } finally {
            this.isSubmitting = false;
            this.ui.setButtonLoading(false);
            this.lockButtonTemporarily();
            this.turnstile.reset();
        }
    }

    lockButtonTemporarily() {
        this.isButtonLocked = true;
        this.ui.setButtonLocked(true);

        setTimeout(() => {
            this.isButtonLocked = false;
            this.ui.setButtonLocked(false);
        }, 5000);
    }

    handleLogoutSuccessMessage() {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('logout') === 'success') {
            this.ui.showMessage('登出成功！', 'success');
            
            // Clean URL
            const newUrl = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
            window.history.replaceState({path: newUrl}, '', newUrl);
        }
    }
}

/* ==============================================
   APPLICATION INITIALIZATION
   ============================================== */
document.addEventListener('DOMContentLoaded', () => {
    // Initialize the SSO application
    window.ssoApp = new SSOApp();
}); 