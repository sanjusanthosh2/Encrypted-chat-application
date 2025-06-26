/**
 * Simple Chat Application - Main JavaScript File
 * Session-based authentication (no JWT complexity)
 */

// Global application state
let appState = {
    currentUser: null,
    encryptionKey: null,
    isLoggedIn: false
};

// API Base URL
const API_BASE = window.location.origin;

/**
 * Authentication Functions
 */

// Check if user is authenticated (simplified)
function isAuthenticated() {
    return !!localStorage.getItem('user_info');
}

// Get user information from localStorage
function getCurrentUser() {
    const userInfo = localStorage.getItem('user_info');
    return userInfo ? JSON.parse(userInfo) : null;
}

// Update authentication UI based on login status
function updateAuthUI() {
    const isLoggedIn = isAuthenticated();
    const userInfo = getCurrentUser();
    
    // Navigation elements
    const loginNav = document.getElementById('login-nav');
    const registerNav = document.getElementById('register-nav');
    const userNav = document.getElementById('user-nav');
    const chatNav = document.getElementById('chat-nav');
    const profileNav = document.getElementById('profile-nav');
    const userName = document.getElementById('user-name');
    
    if (isLoggedIn && userInfo) {
        // Show authenticated UI
        if (loginNav) loginNav.style.display = 'none';
        if (registerNav) registerNav.style.display = 'none';
        if (userNav) userNav.style.display = 'block';
        if (chatNav) chatNav.style.display = 'block';
        if (profileNav) profileNav.style.display = 'block';
        if (userName) userName.textContent = userInfo.username;
        
        appState.isLoggedIn = true;
        appState.currentUser = userInfo;
        appState.encryptionKey = localStorage.getItem('encryption_key');
    } else {
        // Show unauthenticated UI
        if (loginNav) loginNav.style.display = 'block';
        if (registerNav) registerNav.style.display = 'block';
        if (userNav) userNav.style.display = 'none';
        if (chatNav) chatNav.style.display = 'none';
        if (profileNav) profileNav.style.display = 'none';
        
        appState.isLoggedIn = false;
        appState.currentUser = null;
        appState.encryptionKey = null;
    }
}

// Logout function
async function logout() {
    try {
        console.log('Logout initiated');
        
        // Call logout API to clear server session
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'  // Include session cookie
        });
        
        // Clear local storage
        localStorage.removeItem('user_info');
        localStorage.removeItem('encryption_key');
        
        console.log('Logout completed, localStorage cleared');
        
        // Update UI
        updateAuthUI();
        
        // Show success message
        showAlert('Logged out successfully', 'success');
        
        // Redirect to home page
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
        
    } catch (error) {
        console.error('Logout error:', error);
        
        // Force logout even if API call fails
        localStorage.clear();
        window.location.href = '/';
    }
}

/**
 * HTTP Request Functions (Simplified - No JWT)
 */

// Fetch with session credentials (no JWT headers needed)
async function fetchWithAuth(url, options = {}) {
    const defaultOptions = {
        credentials: 'include',  // Include session cookie
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };
    
    try {
        const response = await fetch(url, defaultOptions);
        
        // Handle authentication errors
        if (response.status === 401) {
            console.log('Authentication failed, redirecting to login');
            localStorage.clear();
            window.location.href = '/login';
            throw new Error('Authentication failed');
        }
        
        return response;
        
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}

/**
 * UI Utility Functions
 */

// Show alert message
function showAlert(message, type = 'info', duration = 5000) {
    const alertContainer = document.getElementById('alert-container');
    
    if (!alertContainer) {
        console.warn('Alert container not found');
        return;
    }
    
    // Create alert element
    const alertId = 'alert-' + Date.now();
    const alertHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" id="${alertId}" role="alert">
            <i class="bi bi-${getAlertIcon(type)}"></i>
            ${escapeHtml(message)}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Add to container
    alertContainer.insertAdjacentHTML('afterbegin', alertHTML);
    
    // Auto-remove after duration
    if (duration > 0) {
        setTimeout(() => {
            const alertElement = document.getElementById(alertId);
            if (alertElement) {
                const bsAlert = new bootstrap.Alert(alertElement);
                bsAlert.close();
            }
        }, duration);
    }
}

// Get appropriate icon for alert type
function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle-fill',
        'danger': 'exclamation-triangle-fill',
        'warning': 'exclamation-triangle-fill',
        'info': 'info-circle-fill',
        'primary': 'info-circle-fill',
        'secondary': 'info-circle-fill'
    };
    
    return icons[type] || 'info-circle-fill';
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format timestamp for display
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }
    
    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
    }
    
    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    }
    
    // Same year
    if (date.getFullYear() === now.getFullYear()) {
        return date.toLocaleDateString('en-US', { 
            month: 'short', 
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    // Different year
    return date.toLocaleDateString('en-US', { 
        year: 'numeric',
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Debounce function for search inputs
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Validate username format
function isValidUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
}

/**
 * Application Initialization
 */

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Update authentication UI
    updateAuthUI();
    
    // Set up global event listeners
    setupGlobalEventListeners();
    
    // Initialize any page-specific functionality
    initializePageSpecificFeatures();
});

// Set up global event listeners
function setupGlobalEventListeners() {
    // Handle form submissions with loading states
    document.addEventListener('submit', function(event) {
        const form = event.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        if (submitBtn && !submitBtn.disabled) {
            // Add loading state
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
            submitBtn.disabled = true;
            
            // Reset after 10 seconds if form hasn't been reset
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            }, 10000);
        }
    });
    
    // Handle escape key to close modals
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const openModal = document.querySelector('.modal.show');
            if (openModal) {
                const modalInstance = bootstrap.Modal.getInstance(openModal);
                if (modalInstance) {
                    modalInstance.hide();
                }
            }
        }
    });
}

// Initialize page-specific features based on current page
function initializePageSpecificFeatures() {
    const path = window.location.pathname;
    
    switch (path) {
        case '/':
            console.log('Home page initialized');
            break;
        case '/login':
            console.log('Login page initialized');
            break;
        case '/register':
            console.log('Register page initialized');
            break;
        case '/chat':
            console.log('Chat page initialized');
            break;
        case '/profile':
            console.log('Profile page initialized');
            break;
    }
}

/**
 * Export functions for use in other scripts
 */
window.EncryptedChat = {
    // Authentication
    isAuthenticated,
    logout,
    updateAuthUI,
    
    // HTTP
    fetchWithAuth,
    
    // Utilities
    showAlert,
    escapeHtml,
    formatTimestamp,
    debounce,
    isValidEmail,
    isValidUsername,
    
    // State
    appState
};