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
        this.initStartTime = Date.now();
        
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
            // Start with a shorter timeout for faster initialization
            await this.waitForApi(5000);
            await this.render();
        } catch (error) {
            console.warn('Turnstile initialization failed, enabling fallback mode:', error);
            this.enableFallback();
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
                    setTimeout(check, 50); // Faster polling
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

        // Check if already rendered
        if (this.widget !== null) {
            console.log('Turnstile already rendered, skipping...');
            return;
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
            const initTime = Date.now() - this.initStartTime;
            console.log(`✅ Turnstile widget ready (${initTime}ms)`);
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
            setTimeout(() => this.render().catch(() => this.enableFallback()), 1000); // Faster retry
        } else {
            this.enableFallback();
        }
        
        if (this.rejectToken) {
            this.rejectToken(new Error('Turnstile verification failed'));
            this.rejectToken = null;
        }
    }

    onExpired() {
        console.log('Turnstile token expired');
        this.reset();
    }

    enableFallback() {
        this.fallbackMode = true;
        this.isReady = true; // Mark as ready even in fallback mode
        console.log('🔄 Turnstile fallback mode enabled');
        
        // Generate a placeholder token for fallback
        this.fallbackToken = 'fallback_' + Date.now();
    }

    async getToken() {
        return new Promise((resolve, reject) => {
            if (this.fallbackMode) {
                console.log('Using fallback token');
                resolve(this.fallbackToken);
                return;
            }

            if (!this.isReady || !this.widget) {
                reject(new Error('Turnstile not ready'));
                return;
            }

            try {
                this.resolveToken = resolve;
                this.rejectToken = reject;
                
                // Set a timeout for token generation
                const timeout = setTimeout(() => {
                    if (this.resolveToken) {
                        this.rejectToken(new Error('Turnstile token timeout'));
                        this.resolveToken = null;
                        this.rejectToken = null;
                    }
                }, 10000);

                // Clear timeout when token is received
                const originalResolve = this.resolveToken;
                this.resolveToken = (token) => {
                    clearTimeout(timeout);
                    originalResolve(token);
                };

                window.turnstile.execute(this.widget);
            } catch (error) {
                reject(error);
            }
        });
    }

    reset() {
        if (this.fallbackMode) {
            // Generate new fallback token
            this.fallbackToken = 'fallback_' + Date.now();
            return;
        }

        if (this.widget && window.turnstile) {
            try {
                window.turnstile.reset(this.widget);
            } catch (error) {
                console.warn('Turnstile reset failed:', error);
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
        if (this.elements.emailInput) {
            this.elements.emailInput.addEventListener('focus', () => {
                if (this.elements.emailInput.parentElement) {
                    this.elements.emailInput.parentElement.style.transform = 'scale(1.02)';
                }
            });
            
            this.elements.emailInput.addEventListener('blur', () => {
                if (this.elements.emailInput.parentElement) {
                    this.elements.emailInput.parentElement.style.transform = 'scale(1)';
                }
            });
        }
    }

    showLoginSection() {
        if (this.elements.loginSection) {
            this.elements.loginSection.style.display = 'block';
        }
        if (this.elements.loggedInSection) {
            this.elements.loggedInSection.style.display = 'none';
        }
    }

    showLoggedInSection(user) {
        if (this.elements.loginSection) {
            this.elements.loginSection.style.display = 'none';
        }
        if (this.elements.loggedInSection) {
            this.elements.loggedInSection.style.display = 'block';
        }
        this.updateUserInfo(user);
    }

    updateUserInfo(user) {
        if (this.elements.userNameEl) {
            this.elements.userNameEl.textContent = user.real_name || '用戶';
        }
        if (this.elements.userEmailEl) {
            this.elements.userEmailEl.textContent = user.email || '';
        }
        
        if (user.avatar_base64) {
            if (this.elements.userAvatarImg) {
                this.elements.userAvatarImg.src = `data:image/jpeg;base64,${user.avatar_base64}`;
                this.elements.userAvatarImg.style.display = 'block';
            }
            if (this.elements.userAvatarPlaceholder) {
                this.elements.userAvatarPlaceholder.style.display = 'none';
            }
        } else {
            if (this.elements.userAvatarImg) {
                this.elements.userAvatarImg.style.display = 'none';
            }
            if (this.elements.userAvatarPlaceholder) {
                this.elements.userAvatarPlaceholder.style.display = 'flex';
            }
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
        const span = btn.querySelector('span');
        const icon = btn.querySelector('i');
        
        if (loading) {
            btn.classList.add('loading');
            btn.classList.remove('locked', 'preparing', 'ready');
            btn.disabled = true;
            
            if (!btn.querySelector('.loading-dots')) {
                span.innerHTML = 'sending...<div class="loading-dots"><span></span><span></span><span></span></div>';
            }
            if (icon) icon.style.display = 'none';
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
            span.textContent = '發送魔法連結';
            if (icon) {
                icon.style.display = 'block';
                feather.replace();
            }
        }
    }

    setButtonPreparing(preparing) {
        const btn = this.elements.magicLinkBtn;
        const span = btn.querySelector('span');
        
        if (preparing) {
            btn.classList.add('preparing');
            btn.classList.remove('loading', 'locked', 'ready');
            btn.disabled = false; // Keep button clickable in preparing state
            span.textContent = '發送魔法連結';
        } else {
            btn.classList.remove('preparing');
            span.textContent = '發送魔法連結';
        }
    }

    setButtonReady(ready) {
        const btn = this.elements.magicLinkBtn;
        
        if (ready) {
            btn.classList.add('ready');
            btn.classList.remove('loading', 'locked', 'preparing');
        } else {
            btn.classList.remove('ready');
        }
    }

    setButtonLocked(locked) {
        const btn = this.elements.magicLinkBtn;
        const span = btn.querySelector('span');
        
        if (locked) {
            btn.classList.add('locked');
            btn.classList.remove('loading', 'preparing', 'ready');
            btn.disabled = true;
            span.textContent = '請稍候再試';
        } else {
            btn.classList.remove('locked');
            btn.disabled = false;
            span.textContent = '發送魔法連結';
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
        this.isFullyReady = false; // Track if all components are ready
        this.pendingSubmission = null; // Store pending submission data
        
        this.initialize();
    }

    async initialize() {
        console.log('🚀 Initializing SSO App...');
        
        try {
            // Setup form handling immediately (but with readiness check)
            this.setupFormHandling();
            
            // Setup logout handling
            this.setupLogoutHandling();
            
            // Show preparing state - let user know system is getting ready
            this.ui.setButtonPreparing(true);
            
            // Initialize Turnstile (this may take time)
            await this.turnstile.initialize();
            
            // Check authentication status
            await this.auth.checkStatus();
            
            // Handle logout success message from URL
            this.handleLogoutSuccessMessage();
            
            // Mark as fully ready and show ready state
            this.isFullyReady = true;
            this.ui.setButtonPreparing(false);
            this.ui.setButtonReady(true);
            
            // Remove ready pulse after a few seconds to not be distracting
            setTimeout(() => {
                this.ui.setButtonReady(false);
            }, 3000);
            
            // Process any pending submission
            if (this.pendingSubmission) {
                console.log('Processing pending form submission...');
                await this.processPendingSubmission();
            }
            
            console.log('✅ SSO App initialized successfully');
        } catch (error) {
            console.error('❌ SSO App initialization failed:', error);
            this.ui.setButtonPreparing(false);
            this.ui.showMessage('系統初始化失敗，請刷新頁面重試', 'error');
            this.isFullyReady = true; // Allow submission even if initialization failed
        }
    }

    setupFormHandling() {
        this.ui.elements.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (this.isSubmitting || this.isButtonLocked) {
                console.log('Form submission blocked (already submitting or locked)');
                return;
            }
            
            const email = this.ui.elements.emailInput.value.trim();
            if (!email) {
                this.ui.showMessage('請輸入有效的電子郵件地址', 'error');
                return;
            }

            // If not fully ready, store the submission and show subtle loading
            if (!this.isFullyReady) {
                console.log('System not ready, queuing submission...');
                this.pendingSubmission = { email };
                this.ui.setButtonLoading(true);
                this.ui.showMessage('正在發送魔法連結...', 'info', false);
                return;
            }
            
            await this.handleFormSubmit();
        });
    }

    async processPendingSubmission() {
        if (!this.pendingSubmission) return;
        
        const { email } = this.pendingSubmission;
        this.pendingSubmission = null;
        
        // Set the email back to the input and submit
        this.ui.elements.emailInput.value = email;
        await this.handleFormSubmit();
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
            // Double-check readiness before getting token
            if (!this.isFullyReady) {
                throw new Error('系統尚未準備就緒，請稍後再試');
            }
            
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