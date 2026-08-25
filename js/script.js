// Cyber Sathi - Main JavaScript

// Navigation toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navToggle.classList.toggle('active');
            navMenu.classList.toggle('active');
            const isExpanded = navToggle.classList.contains('active');
            navToggle.setAttribute('aria-expanded', isExpanded);
        });

        // Close menu when clicking outside
        document.addEventListener('click', function(event) {
            if (!navToggle.contains(event.target) && !navMenu.contains(event.target)) {
                navToggle.classList.remove('active');
                navMenu.classList.remove('active');
                navToggle.setAttribute('aria-expanded', 'false');
            }
        });

        // Close menu when clicking on a link
        const navLinks = navMenu.querySelectorAll('a');
        navLinks.forEach(link => {
            link.addEventListener('click', function() {
                navToggle.classList.remove('active');
                navMenu.classList.remove('active');
                navToggle.setAttribute('aria-expanded', 'false');
            });
        });
    }

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href !== '#') {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });

    // Add scroll-based navbar background
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        window.addEventListener('scroll', function() {
            if (window.scrollY > 50) {
                navbar.style.backgroundColor = 'rgba(5, 8, 24, 0.95)';
            } else {
                navbar.style.backgroundColor = 'rgba(5, 8, 24, 1)';
            }
        });
    }

    // Quick URL form on homepage
    const quickUrlForm = document.getElementById('quick-url-form');
    if (quickUrlForm) {
        quickUrlForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const urlInput = document.getElementById('quick-url-input');
            const quickUrlResult = document.getElementById('quick-url-result');
            
            if (urlInput && urlInput.value) {
                // Redirect to scanner page with the URL
                window.location.href = `scanner.html?url=${encodeURIComponent(urlInput.value)}`;
            }
        });
    }

    // Utility function to get URL parameters
    function getUrlParameter(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    // Check if there's a URL parameter and populate the scanner
    const urlParam = getUrlParameter('url');
    if (urlParam && document.getElementById('url-input')) {
        document.getElementById('url-input').value = urlParam;
    }
});

// Utility functions
const CyberSathiUtils = {
    // Show loading state
    showLoading: function(element) {
        if (element) {
            element.classList.add('loading');
        }
    },

    // Hide loading state
    hideLoading: function(element) {
        if (element) {
            element.classList.remove('loading');
        }
    },

    // Show element
    show: function(element) {
        if (element) {
            element.classList.remove('hidden');
        }
    },

    // Hide element
    hide: function(element) {
        if (element) {
            element.classList.add('hidden');
        }
    },

    // Create security analysis HTML
    createSecurityAnalysis: function(score, riskLevel, warnings, recommendation) {
        const riskClass = this.getRiskClass(riskLevel);
        
        return `
            <div class="security-analysis">
                <h2>SECURITY ANALYSIS</h2>
                <div class="score-display">
                    <div class="score-number">${score}</div>
                    <div class="score-label ${riskClass}">${riskLevel}</div>
                </div>
                <div class="warnings-list">
                    <h3>Warnings:</h3>
                    <ul>
                        ${warnings.map(warning => `<li>${warning}</li>`).join('')}
                    </ul>
                </div>
                <div class="recommendation">
                    <h3>Recommendation:</h3>
                    <p>${recommendation}</p>
                </div>
            </div>
        `;
    },

    // Get CSS class for risk level
    getRiskClass: function(riskLevel) {
        const riskClasses = {
            'LOW RISK': 'low-risk',
            'CAUTION': 'caution',
            'SUSPICIOUS': 'suspicious',
            'HIGH RISK': 'high-risk',
            'VERY HIGH RISK': 'very-high-risk',
            'POTENTIAL SCAM': 'high-risk'
        };
        return riskClasses[riskLevel] || 'suspicious';
    },

    // Create action guide HTML
    createActionGuide: function(steps) {
        return `
            <div class="action-steps">
                ${steps.map(step => `<div>${step}</div>`).join('')}
            </div>
        `;
    },

    // Create red flag component
    createRedFlag: function(message) {
        return `
            <div class="red-flag">
                <h3>🚩 RED FLAG</h3>
                <p>${message}</p>
            </div>
        `;
    },

    // Format URL for display
    formatUrl: function(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch (e) {
            return url;
        }
    },

    // Validate URL format
    isValidUrl: function(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    },

    // Extract domain from URL
    extractDomain: function(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch (e) {
            return null;
        }
    },

    // Check if string contains suspicious keywords
    containsSuspiciousKeywords: function(text, keywords) {
        const lowerText = text.toLowerCase();
        return keywords.some(keyword => lowerText.includes(keyword.toLowerCase()));
    },

    // Debounce function for performance
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Safe HTML escape to prevent XSS
    escapeHtml: function(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    // Generate unique ID
    generateId: function() {
        return 'id-' + Math.random().toString(36).substr(2, 9);
    },

    // Copy text to clipboard
    copyToClipboard: function(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            return new Promise((resolve, reject) => {
                try {
                    document.execCommand('copy');
                    resolve();
                } catch (err) {
                    reject(err);
                } finally {
                    document.body.removeChild(textArea);
                }
            });
        }
    },

    // Show toast notification
    showToast: function(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }
};

// Add CSS animations for toasts
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Export utilities for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CyberSathiUtils;
}