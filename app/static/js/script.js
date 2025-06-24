document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const emailInput = document.getElementById('email');
    const responseMessage = document.getElementById('response-message');
    const magicLinkBtn = loginForm.querySelector('.magic-link-btn');
    
    // UI sections
    const loginSection = document.getElementById('login-section');
    const loggedInSection = document.getElementById('logged-in-section');
    
    // User info elements
    const userNameEl = document.getElementById('user-name');
    const userEmailEl = document.getElementById('user-email');
    const userAvatarImg = document.getElementById('user-avatar-img');
    const userAvatarPlaceholder = document.getElementById('user-avatar-placeholder');
    const logoutBtn = document.getElementById('logout-btn');
    const logoutMessage = document.getElementById('logout-message');
    
    // Check authentication status on page load
    checkAuthStatus();
    
    // Allow button to be clickable immediately, but delay actual submission
    magicLinkBtn.disabled = false;
    console.log('Page loaded, button enabled for immediate interaction');
    
    let turnstileToken = null;
    let turnstileWidgetId = null;
    let isSubmitting = false;
    let isExecuting = false;
    let isButtonLocked = false;
    let isTurnstileReady = false;
    let verificationTimeout = null;
    let isWaitingForTurnstile = false;

    // Authentication functions
    async function checkAuthStatus() {
        try {
            const token = localStorage.getItem('access_token');
            if (!token) {
                showLoginSection();
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
                    showLoggedInSection(data.user);
                } else {
                    localStorage.removeItem('access_token');
                    showLoginSection();
                }
            } else {
                localStorage.removeItem('access_token');
                showLoginSection();
            }
        } catch (error) {
            console.error('Error checking auth status:', error);
            showLoginSection();
        }
    }

    function showLoginSection() {
        loginSection.style.display = 'block';
        loggedInSection.style.display = 'none';
    }

    function showLoggedInSection(user) {
        loginSection.style.display = 'none';
        loggedInSection.style.display = 'block';
        
        // Update user info
        userNameEl.textContent = user.real_name || '用戶';
        userEmailEl.textContent = user.email || '';
        
        // Handle avatar
        if (user.avatar_base64) {
            userAvatarImg.src = `data:image/jpeg;base64,${user.avatar_base64}`;
            userAvatarImg.style.display = 'block';
            userAvatarPlaceholder.style.display = 'none';
        } else {
            userAvatarImg.style.display = 'none';
            userAvatarPlaceholder.style.display = 'flex';
        }
    }

    // Logout function
    async function handleLogout() {
        try {
            logoutBtn.disabled = true;
            logoutBtn.innerHTML = '<span>處理中...</span>';
            
            const response = await fetch('/auth/logout', {
                method: 'POST'
            });
            
            if (response.ok) {
                localStorage.removeItem('access_token');
                showLogoutMessage('登出成功！', 'success');
                
                setTimeout(() => {
                    showLoginSection();
                    hideLogoutMessage();
                }, 1500);
            } else {
                showLogoutMessage('登出失敗，請重試', 'error');
            }
        } catch (error) {
            console.error('Logout error:', error);
            showLogoutMessage('網路錯誤，請重試', 'error');
        } finally {
            logoutBtn.disabled = false;
            logoutBtn.innerHTML = '<i data-feather="log-out"></i><span>登出</span>';
            feather.replace();
        }
    }
    
    function showLogoutMessage(text, type) {
        logoutMessage.textContent = text;
        logoutMessage.className = `${type} show`;
    }
    
    function hideLogoutMessage() {
        logoutMessage.classList.remove('show');
        setTimeout(() => {
            logoutMessage.textContent = '';
            logoutMessage.className = '';
        }, 300);
    }
    
    // Logout button event listener
    logoutBtn.addEventListener('click', handleLogout);

    // Function to show message with animation
    function showMessage(text, type) {
        responseMessage.innerHTML = `<span class="message-text">${text}</span>`;
        responseMessage.className = `${type} show`;
        
        // Auto hide after 5 seconds
        setTimeout(() => {
            hideMessage();
        }, 5000);
    }

    // Function to hide message with animation
    function hideMessage() {
        responseMessage.classList.remove('show');
        setTimeout(() => {
            responseMessage.textContent = '';
            responseMessage.className = '';
        }, 400);
    }

    // Turnstile callback functions
    window.onTurnstileSuccess = function(token) {
        console.log('✅ Step 1: Turnstile verification successful, token:', token.substring(0, 20) + '...');
        turnstileToken = token;
        isExecuting = false;
        
        // Clear verification timeout
        if (verificationTimeout) {
            clearTimeout(verificationTimeout);
            verificationTimeout = null;
            console.log('Verification timeout cleared - success');
        }
        
        // If form was submitted and waiting for turnstile, proceed with submission
        if (isSubmitting) {
            console.log('📤 Step 2: Form is waiting, proceeding with submission');
            submitForm();
        }
    };

    window.onTurnstileError = function(error) {
        console.error('Turnstile error:', error);
        turnstileToken = null;
        isExecuting = false;
        
        // Clear verification timeout
        if (verificationTimeout) {
            clearTimeout(verificationTimeout);
            verificationTimeout = null;
            console.log('Verification timeout cleared - error');
        }
        
        if (isSubmitting) {
            isSubmitting = false;
            showMessage('驗證失敗，正在重新初始化...', 'error');
            resetButton();
            // Destroy and recreate widget after error
            setTimeout(() => {
                destroyAndRecreateWidget();
            }, 1000);
        }
    };

    window.onTurnstileExpired = function() {
        console.log('Turnstile token expired');
        turnstileToken = null;
        isExecuting = false;
        
        // Clear verification timeout
        if (verificationTimeout) {
            clearTimeout(verificationTimeout);
            verificationTimeout = null;
            console.log('Verification timeout cleared - expired');
        }
        
        if (isSubmitting) {
            isSubmitting = false;
            showMessage('驗證已過期，正在重新初始化...', 'error');
            resetButton();
            // Destroy and recreate widget after expiration
            setTimeout(() => {
                destroyAndRecreateWidget();
            }, 1000);
        }
    };

    // Function to reset button state
    function resetButton() {
        magicLinkBtn.classList.remove('loading');
        magicLinkBtn.innerHTML = `
            <span>發送魔法連結</span>
            <i data-feather="arrow-right"></i>
        `;
        feather.replace();
        
        // Clear any existing timeout
        if (verificationTimeout) {
            clearTimeout(verificationTimeout);
            verificationTimeout = null;
        }
        
        // Enable button if not locked (no longer require Turnstile to be ready)
        if (!isButtonLocked) {
            magicLinkBtn.disabled = false;
        }
    }
    
    // Function to update button state based on readiness
    function updateButtonState() {
        // Always keep button enabled unless it's locked or submitting
        if (!isButtonLocked && !isSubmitting) {
            magicLinkBtn.disabled = false;
            console.log('Button enabled - always ready for user interaction');
        } else {
            magicLinkBtn.disabled = true;
            if (isButtonLocked) {
                console.log('Button disabled - locked');
            } else if (isSubmitting) {
                console.log('Button disabled - submitting');
            }
        }
    }
    
    // Function to lock button for 5 seconds
    function lockButtonTemporarily() {
        isButtonLocked = true;
        magicLinkBtn.disabled = true;
        magicLinkBtn.classList.add('locked');
        
        let countdown = 5;
        const originalHTML = magicLinkBtn.innerHTML;
        
        // Update button text with countdown
        const updateCountdown = () => {
            magicLinkBtn.innerHTML = `
                <span>處理中</span>
                <i data-feather="clock"></i>
            `;
            feather.replace();
            countdown--;
            
            if (countdown >= 0) {
                setTimeout(updateCountdown, 1000);
            } else {
                // Unlock button after countdown
                isButtonLocked = false;
                magicLinkBtn.classList.remove('locked');
                magicLinkBtn.innerHTML = originalHTML;
                feather.replace();
                updateButtonState();
                console.log('Button unlocked, ready for next submission');
            }
        };
        
        updateCountdown();
    }

    // Function to refresh Turnstile widget
    function refreshTurnstile() {
        console.log('Refreshing Turnstile widget...');
        
        // Clear all states first
        turnstileToken = null;
        isExecuting = false;
        
        if (window.turnstile && turnstileWidgetId !== null) {
            try {
                // Try to reset the widget
                window.turnstile.reset(turnstileWidgetId);
                console.log('Turnstile widget reset successful');
                
                // Add a small delay to ensure reset is complete
                setTimeout(() => {
                    console.log('Turnstile reset complete, widget ready for next use');
                }, 100);
            } catch (error) {
                console.error('Error resetting Turnstile widget:', error);
                // If reset fails, remove and recreate the widget
                destroyAndRecreateWidget();
            }
        } else {
            console.log('No Turnstile widget to refresh or API not available');
            // Try to create a new widget if none exists
            if (window.turnstile) {
                setTimeout(() => {
                    renderTurnstile();
                }, 200);
            }
        }
    }
    
    // Function to completely destroy and recreate the widget
    function destroyAndRecreateWidget() {
        console.log('Destroying and recreating Turnstile widget...');
        
        // Clear widget ID and mark as not ready
        turnstileWidgetId = null;
        turnstileToken = null;
        isExecuting = false;
        isTurnstileReady = false;
        
        // Clear any existing timeout
        if (verificationTimeout) {
            clearTimeout(verificationTimeout);
            verificationTimeout = null;
        }
        
        // Update button state
        updateButtonState();
        
        // Clear the container
        const turnstileElement = document.querySelector('.cf-turnstile');
        if (turnstileElement) {
            turnstileElement.innerHTML = '';
        }
        
        // Recreate after a delay
        setTimeout(() => {
            console.log('Recreating Turnstile widget...');
            renderTurnstile();
        }, 500);
    }
    
    // Function to handle verification timeout
    function handleVerificationTimeout() {
        console.log('⏰ Verification timeout - resetting and retrying...');
        
        // Clear timeout
        verificationTimeout = null;
        
        // Reset states
        isSubmitting = false;
        isExecuting = false;
        
        // Show timeout message
        showMessage('驗證超時，請重新嘗試...', 'error');
        
        // Reset button
        resetButton();
        
        // Destroy and recreate widget
        setTimeout(() => {
            destroyAndRecreateWidget();
        }, 1000);
    }

    // Function to render Turnstile widget
    function renderTurnstile() {
        if (window.turnstile) {
            const turnstileElement = document.querySelector('.cf-turnstile');
            
            // Check if widget is already rendered
            if (turnstileWidgetId !== null) {
                console.log('Turnstile widget already exists with ID:', turnstileWidgetId);
                return;
            }
            
            if (turnstileElement) {
                // Check if element already has a widget
                if (turnstileElement.innerHTML.trim() !== '') {
                    console.log('Turnstile element already contains content, clearing...');
                    turnstileElement.innerHTML = '';
                }
                
                // Try to get sitekey from multiple sources
                let sitekey = turnstileElement.getAttribute('data-sitekey');
                
                // Fallback to global variable if data attribute is empty
                if (!sitekey || sitekey.trim() === '') {
                    sitekey = window.TURNSTILE_SITE_KEY;
                    console.log('Using global TURNSTILE_SITE_KEY:', sitekey);
                }
                
                console.log('Attempting to render Turnstile with sitekey:', sitekey);
                
                if (!sitekey || sitekey.trim() === '') {
                    console.error('Turnstile sitekey is empty or undefined from both sources');
                    return;
                }
                
                try {
                    turnstileWidgetId = window.turnstile.render(turnstileElement, {
                        sitekey: sitekey,
                        callback: 'onTurnstileSuccess',
                        'error-callback': 'onTurnstileError',
                        'expired-callback': 'onTurnstileExpired',
                        theme: 'dark',
                        size: 'invisible'
                    });
                    console.log('Turnstile widget rendered with ID:', turnstileWidgetId);
                    
                    // Mark Turnstile as ready and update button state
                    isTurnstileReady = true;
                    updateButtonState();
                } catch (error) {
                    console.error('Error rendering Turnstile:', error);
                    turnstileWidgetId = null;
                }
            } else {
                console.log('Turnstile element not found');
            }
        } else {
            console.log('Turnstile API not loaded yet');
        }
    }

    // Wait for Turnstile to load and render widget
    function waitForTurnstile() {
        if (window.turnstile) {
            renderTurnstile();
        } else {
            setTimeout(waitForTurnstile, 100);
        }
    }

    // Wait for Turnstile to be ready with delay mechanism
    async function waitForTurnstileWithDelay() {
        console.log('🔄 Starting delayed verification process...');
        
        // Show countdown while waiting for Turnstile to be ready
        let countdown = 5;
        
        const countdownInterval = setInterval(() => {
            if (countdown > 0) {
                magicLinkBtn.innerHTML = `
                    <span>處理中</span>
                    <div class="loading-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                `;
                countdown--;
            } else {
                clearInterval(countdownInterval);
                
                // Change to verification state
                magicLinkBtn.innerHTML = `
                    <span>處理中</span>
                    <div class="loading-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                `;
                console.log('⏰ Delay period complete, proceeding with verification');
            }
        }, 1000);

        // Wait for the delay period and ensure Turnstile is ready
        await new Promise(resolve => {
            const checkReady = () => {
                if (countdown <= 0 && (isTurnstileReady || window.turnstile)) {
                    // Ensure widget is rendered if not already
                    if (!isTurnstileReady && window.turnstile) {
                        renderTurnstile();
                    }
                    resolve();
                } else {
                    setTimeout(checkReady, 100);
                }
            };
            checkReady();
        });
        
        console.log('✅ Verification preparation complete');
    }

    // Start waiting for Turnstile
    waitForTurnstile();

    // Function to actually submit the form
    async function submitForm() {
        if (!turnstileToken) {
            showMessage('驗證失敗，請重新嘗試。', 'error');
            resetButton();
            refreshTurnstile();
            return;
        }

        const email = emailInput.value;
        const tokenToUse = turnstileToken; // Store token before clearing
        
        // Clear token immediately after capturing it for use
        turnstileToken = null;
        console.log('🔄 Step 3: Token captured and cleared for submission');

        try {
            const response = await fetch('/auth/magic-link', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    email: email,
                    turnstile_token: tokenToUse
                }),
            });

            const data = await response.json();

            // Add a small delay for better UX
            await new Promise(resolve => setTimeout(resolve, 800));

            if (response.ok) {
                showMessage(data.message || '魔法連結已發送到您的 Email！', 'success');
                emailInput.value = '';
                
                // Add success animation to input
                emailInput.style.borderColor = 'var(--success-color)';
                setTimeout(() => {
                    emailInput.style.borderColor = '';
                }, 2000);
            } else {
                showMessage(data.detail || '發生錯誤，請稍後再試。', 'error');
                
                // Add error shake animation
                emailInput.style.animation = 'shake 0.5s ease-in-out';
                setTimeout(() => {
                    emailInput.style.animation = '';
                }, 500);
            }
        } catch (error) {
            console.error('Error requesting magic link:', error);
            await new Promise(resolve => setTimeout(resolve, 800));
            showMessage('網路錯誤，請檢查您的網路連線。', 'error');
            
            // Add error shake animation
            emailInput.style.animation = 'shake 0.5s ease-in-out';
            setTimeout(() => {
                emailInput.style.animation = '';
            }, 500);
        } finally {
            isSubmitting = false;
            resetButton();
            
            // Ensure token is cleared (already cleared in submitForm, but double-check)
            if (turnstileToken) {
                turnstileToken = null;
                console.log('Token cleared in finally block');
            }
            
            // Lock button for 5 seconds to prevent rapid submissions
            console.log('🔒 Step 4: Locking button for 5 seconds');
            lockButtonTemporarily();
            
            // Refresh Turnstile widget with delay for next submission
            setTimeout(() => {
                console.log('🔄 Step 5: Refreshing Turnstile widget for next use');
                refreshTurnstile();
            }, 500);
        }
    }

    // Form submission handler
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (isSubmitting) {
            return; // Prevent double submission
        }
        
        if (isButtonLocked) {
            console.log('Button is locked, submission blocked');
            return; // Prevent submission during lock period
        }

        const email = emailInput.value;
        if (!email) {
            showMessage('請輸入電子郵件地址。', 'error');
            return;
        }

        hideMessage();
        isSubmitting = true;

        // Show loading state with smooth animation
        magicLinkBtn.disabled = true;
        magicLinkBtn.classList.add('loading');
        
        // Initial loading state - preparing for verification
        magicLinkBtn.innerHTML = `
            <span>處理中</span>
            <div class="loading-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        `;

        // Wait for Turnstile to be ready with a delay mechanism
        await waitForTurnstileWithDelay();

        // If Turnstile token is already available, submit immediately
        if (turnstileToken) {
            submitForm();
        } else {
            // Execute Turnstile challenge
            if (window.turnstile && turnstileWidgetId !== null) {
                try {
                    // Check if widget is already executing
                    if (isExecuting) {
                        console.log('Turnstile is already executing, waiting...');
                        return;
                    }
                    
                    // Check if widget already has a valid response
                    let widgetState = null;
                    try {
                        widgetState = window.turnstile.getResponse(turnstileWidgetId);
                    } catch (getResponseError) {
                        console.log('Could not get widget response, proceeding with execution');
                    }
                    
                    if (widgetState && widgetState.trim() !== '') {
                        console.log('Widget already has response, using existing token');
                        turnstileToken = widgetState;
                        submitForm();
                    } else {
                        console.log('Executing Turnstile challenge');
                        isExecuting = true;
                        
                        // Set timeout for verification (15 seconds)
                        verificationTimeout = setTimeout(() => {
                            if (isExecuting && isSubmitting) {
                                console.log('Verification taking too long, triggering timeout');
                                handleVerificationTimeout();
                            }
                        }, 15000);
                        
                        // Add a small delay to ensure widget is ready
                        setTimeout(() => {
                            try {
                                window.turnstile.execute(turnstileWidgetId);
                            } catch (executeError) {
                                console.error('Execute error:', executeError);
                                isExecuting = false;
                                
                                // Clear timeout on immediate error
                                if (verificationTimeout) {
                                    clearTimeout(verificationTimeout);
                                    verificationTimeout = null;
                                }
                                
                                // Try to reset and recreate if execute fails
                                console.log('Execute failed, attempting to reset and recreate widget');
                                isSubmitting = false;
                                showMessage('驗證系統錯誤，正在重新初始化...', 'error');
                                resetButton();
                                destroyAndRecreateWidget();
                            }
                        }, 100);
                    }
                } catch (error) {
                    console.error('Error in Turnstile execution flow:', error);
                    isExecuting = false;
                    isSubmitting = false;
                    showMessage('驗證系統錯誤，請重新嘗試。', 'error');
                    resetButton();
                    destroyAndRecreateWidget();
                }
            } else {
                isSubmitting = false;
                showMessage('驗證系統尚未準備就緒，請稍後再試。', 'error');
                resetButton();
                
                // Try to render widget if it doesn't exist
                if (window.turnstile) {
                    setTimeout(() => {
                        renderTurnstile();
                    }, 500);
                }
            }
        }
    });

    // Add interactive effects
    emailInput.addEventListener('input', () => {
        hideMessage();
        emailInput.style.borderColor = '';
        emailInput.style.animation = '';
    });

    // Add focus effects
    emailInput.addEventListener('focus', () => {
        emailInput.parentElement.style.transform = 'scale(1.02)';
    });

    emailInput.addEventListener('blur', () => {
        emailInput.parentElement.style.transform = 'scale(1)';
    });
}); 