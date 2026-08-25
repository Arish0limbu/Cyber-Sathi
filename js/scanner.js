// Cyber Sathi - URL Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const scannerResult = document.getElementById('scanner-result');
    const analysisDetails = document.getElementById('analysis-details');
    const actionGuide = document.getElementById('action-guide');

    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            e.preventDefault();
            analyzeUrl(urlInput.value);
        });
    }

    // Also handle store checker form
    const storeForm = document.getElementById('store-form');
    if (storeForm) {
        storeForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const storeUrlInput = document.getElementById('store-url-input');
            analyzeUrl(storeUrlInput.value, true);
        });
    }

    function analyzeUrl(url, isStore = false) {
        if (!url) {
            CyberSathiUtils.showToast('Please enter a URL', 'error');
            return;
        }

        // Add https:// if missing for validation
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        if (!CyberSathiUtils.isValidUrl(url)) {
            CyberSathiUtils.showToast('Please enter a valid URL', 'error');
            return;
        }

        // Show loading state
        const targetBtn = isStore ? document.getElementById('analyze-store-btn') : scanBtn;
        if (targetBtn) {
            CyberSathiUtils.showLoading(targetBtn);
        }

        // Simulate analysis delay
        setTimeout(() => {
            const analysis = performUrlAnalysis(url, isStore);
            displayResults(analysis);

            // Hide loading state
            if (targetBtn) {
                CyberSathiUtils.hideLoading(targetBtn);
            }
        }, 1500);
    }

    function performUrlAnalysis(url, isStore) {
        const warnings = [];
        let score = 0;
        const domain = CyberSathiUtils.extractDomain(url);

        // Check HTTPS
        if (!url.startsWith('https://')) {
            warnings.push('⚠ No HTTPS encryption');
            score += 15;
        }

        // Check for IP-based URL
        if (/^(\d{1,3}\.){3}\d{1,3}/.test(domain)) {
            warnings.push('⚠ IP-based URL detected');
            score += 25;
        }

        // Check for punycode (internationalized domain names)
        if (domain.includes('xn--')) {
            warnings.push('⚠ Punycode domain detected (possible homograph attack)');
            score += 20;
        }

        // Check for excessive subdomains
        const subdomainCount = domain.split('.').length - 2;
        if (subdomainCount > 3) {
            warnings.push('⚠ Excessive subdomains');
            score += 10;
        }

        // Check URL length
        if (url.length > 200) {
            warnings.push('⚠ Excessive URL length');
            score += 10;
        }

        // Check for suspicious ports
        if (url.includes(':') && !url.match(/:(80|443|8080)\//)) {
            warnings.push('⚠ Non-standard port detected');
            score += 15;
        }

        // Check for suspicious keywords
        const suspiciousKeywords = [
            'login', 'signin', 'verify', 'account', 'secure', 'bank',
            'update', 'confirm', 'wallet', 'crypto', 'bitcoin',
            'investment', 'profit', 'bonus', 'reward', 'prize'
        ];
        
        const foundKeywords = suspiciousKeywords.filter(keyword => 
            url.toLowerCase().includes(keyword)
        );
        
        if (foundKeywords.length > 0) {
            warnings.push(`⚠ Suspicious keywords detected: ${foundKeywords.join(', ')}`);
            score += foundKeywords.length * 5;
        }

        // Check for suspicious patterns
        const suspiciousPatterns = [
            /@/, // username in URL
            /\.\./, // directory traversal
            /%[0-9a-f]{2}/i, // URL encoding
            /php\?/, // PHP parameter
            /\.exe$/i, // executable file
            /\.zip$/i, // zip file
            /\.rar$/i // rar file
        ];

        suspiciousPatterns.forEach(pattern => {
            if (pattern.test(url)) {
                warnings.push('⚠ Suspicious URL pattern detected');
                score += 10;
            }
        });

        // Check domain spelling (basic check for character repetition)
        if (/(.)\1{3,}/.test(domain)) {
            warnings.push('⚠ Suspicious character repetition in domain');
            score += 10;
        }

        // Store-specific checks
        if (isStore) {
            const storeKeywords = ['shop', 'store', 'buy', 'sale', 'discount', 'cheap', 'free'];
            const foundStoreKeywords = storeKeywords.filter(keyword => 
                url.toLowerCase().includes(keyword)
            );
            
            if (foundStoreKeywords.length > 2) {
                warnings.push('⚠ Multiple shopping-related keywords (possible fake store)');
                score += 10;
            }
        }

        // Cap score at 100
        score = Math.min(score, 100);

        // Determine risk level
        let riskLevel;
        if (score <= 20) {
            riskLevel = 'LOW RISK';
        } else if (score <= 40) {
            riskLevel = 'CAUTION';
        } else if (score <= 60) {
            riskLevel = 'SUSPICIOUS';
        } else if (score <= 80) {
            riskLevel = 'HIGH RISK';
        } else {
            riskLevel = 'VERY HIGH RISK';
        }

        // Generate recommendation
        let recommendation;
        if (score <= 20) {
            recommendation = 'This URL appears to have few suspicious indicators. However, always verify the website independently before entering sensitive information.';
        } else if (score <= 40) {
            recommendation = 'Exercise caution with this URL. Verify the website through official channels and look for additional security indicators.';
        } else if (score <= 60) {
            recommendation = 'This URL shows several suspicious indicators. Do not enter sensitive information. Verify the website independently through official channels.';
        } else if (score <= 80) {
            recommendation = 'This URL has multiple suspicious characteristics. Avoid entering any information. Close the page and verify through official channels.';
        } else {
            recommendation = 'This URL exhibits very high-risk characteristics. Do not interact with this page. Close it immediately and report if possible.';
        }

        return {
            url: url,
            domain: domain,
            score: score,
            riskLevel: riskLevel,
            warnings: warnings,
            recommendation: recommendation,
            hasHttps: url.startsWith('https://'),
            subdomainCount: subdomainCount,
            urlLength: url.length
        };
    }

    function displayResults(analysis) {
        // Display security analysis
        if (scannerResult) {
            scannerResult.innerHTML = CyberSathiUtils.createSecurityAnalysis(
                analysis.score,
                analysis.riskLevel,
                analysis.warnings,
                analysis.recommendation
            );
        }

        // Display detailed analysis
        if (analysisDetails) {
            CyberSathiUtils.show(analysisDetails);
            
            document.getElementById('url-structure').innerHTML = `
                <div class="analysis-item">
                    <strong>Domain:</strong> ${CyberSathiUtils.escapeHtml(analysis.domain)}
                </div>
                <div class="analysis-item">
                    <strong>HTTPS:</strong> ${analysis.hasHttps ? '✓ Yes' : '✗ No'}
                </div>
                <div class="analysis-item">
                    <strong>Subdomains:</strong> ${analysis.subdomainCount}
                </div>
                <div class="analysis-item">
                    <strong>URL Length:</strong> ${analysis.urlLength} characters
                </div>
            `;

            document.getElementById('security-indicators').innerHTML = `
                <div class="analysis-item">
                    <strong>Encryption:</strong> ${analysis.hasHttps ? '✓ HTTPS enabled' : '✗ No HTTPS'}
                </div>
                <div class="analysis-item">
                    <strong>Format:</strong> ${CyberSathiUtils.isValidUrl(analysis.url) ? '✓ Valid URL format' : '✗ Invalid URL format'}
                </div>
                <div class="analysis-item">
                    <strong>Structure:</strong> ${analysis.subdomainCount <= 3 ? '✓ Normal subdomain count' : '⚠ Excessive subdomains'}
                </div>
            `;

            document.getElementById('risk-factors').innerHTML = `
                <div class="analysis-item">
                    <strong>Base Score:</strong> ${analysis.score}/100
                </div>
                <div class="analysis-item">
                    <strong>Risk Level:</strong> ${analysis.riskLevel}
                </div>
                <div class="analysis-item">
                    <strong>Warning Count:</strong> ${analysis.warnings.length}
                </div>
            `;
        }

        // Display action guide
        if (actionGuide) {
            CyberSathiUtils.show(actionGuide);
            
            const steps = getActionSteps(analysis.riskLevel);
            document.getElementById('action-steps').innerHTML = CyberSathiUtils.createActionGuide(steps);
        }
    }

    function getActionSteps(riskLevel) {
        const baseSteps = [
            'Do not enter any personal information, passwords, or payment details',
            'Close the page if you haven\'t already',
            'Verify the website through official channels (type the official URL directly)'
        ];

        if (riskLevel === 'HIGH RISK' || riskLevel === 'VERY HIGH RISK') {
            return [
                ...baseSteps,
                'Clear your browser cache and cookies',
                'Run a security scan on your device',
                'Report the URL to relevant authorities if possible'
            ];
        } else if (riskLevel === 'SUSPICIOUS' || riskLevel === 'CAUTION') {
            return [
                ...baseSteps,
                'Look for additional security indicators (HTTPS, valid certificates)',
                'Contact the organization through official channels to verify'
            ];
        } else {
            return [
                ...baseSteps,
                'Continue to monitor for any suspicious activity',
                'Bookmark the official site for future reference'
            ];
        }
    }
});

// Future API integration placeholder
/*
 * FUTURE API INTEGRATION
 * 
 * This section is reserved for future integration with external threat intelligence APIs.
 * 
 * Possible integrations:
 * - Google Safe Browsing API
 * - VirusTotal URL analysis
 * - URLVoid reputation check
 * - WhoisXML API for domain analysis
 * 
 * Example implementation:
 * 
 * async function checkWithThreatAPI(url) {
 *     const API_KEY = 'YOUR_API_KEY'; // Never commit real API keys
 *     const response = await fetch(`https://api.example.com/check?url=${encodeURIComponent(url)}`, {
 *         headers: {
 *             'Authorization': `Bearer ${API_KEY}`
 *         }
 *     });
 *     return await response.json();
 * }
 * 
 * IMPORTANT: Never place real API keys in frontend JavaScript.
 * Use environment variables or server-side proxy for API calls.
 */