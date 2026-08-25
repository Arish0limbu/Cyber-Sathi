// Cyber Sathi - Screenshot Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const screenshotForm = document.getElementById('screenshot-form');
    const screenshotInput = document.getElementById('screenshot-input');
    const analyzeScreenshotBtn = document.getElementById('analyze-screenshot-btn');
    const scannerResult = document.getElementById('scanner-result');
    const screenshotAnalysisResult = document.getElementById('screenshot-analysis-result');
    const detectedIndicators = document.getElementById('detected-indicators');
    const screenshotActionGuide = document.getElementById('screenshot-action-guide');

    // File upload handling
    if (screenshotInput) {
        screenshotInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const preview = document.getElementById('screenshot-preview');
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    preview.innerHTML = `<img src="${e.target.result}" alt="Screenshot Preview">`;
                };
                
                reader.readAsDataURL(file);
            }
        });
    }

    // Screenshot form submission
    if (screenshotForm) {
        screenshotForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const file = screenshotInput.files[0];
            const screenshotType = document.getElementById('screenshot-type-select').value;
            
            if (file) {
                analyzeScreenshot(file, screenshotType);
            } else {
                CyberSathiUtils.showToast('Please select a screenshot', 'error');
            }
        });
    }

    function analyzeScreenshot(file, type) {
        // Show loading state
        if (analyzeScreenshotBtn) {
            CyberSathiUtils.showLoading(analyzeScreenshotBtn);
        }

        // Simulate analysis
        setTimeout(() => {
            const analysis = performScreenshotAnalysis(file, type);
            displayScreenshotResults(analysis);

            // Hide loading state
            if (analyzeScreenshotBtn) {
                CyberSathiUtils.hideLoading(analyzeScreenshotBtn);
            }
        }, 2000);
    }

    function performScreenshotAnalysis(file, type) {
        const indicators = [];
        let score = 0;

        // OCR-ready: In a real implementation, this would extract text from the image
        // const extractedText = await extractScreenshotText(file);
        
        // For demo purposes, we'll analyze based on the type and simulate detection
        const typeSpecificIndicators = getTypeSpecificIndicators(type);
        indicators.push(...typeSpecificIndicators);

        // Common scam indicators
        const commonIndicators = [
            { text: 'act now', severity: 'high', points: 15 },
            { text: 'immediate action', severity: 'high', points: 15 },
            { text: 'account will be closed', severity: 'high', points: 20 },
            { text: 'last chance', severity: 'medium', points: 10 },
            { text: 'send money', severity: 'high', points: 20 },
            { text: 'pay fee', severity: 'high', points: 15 },
            { text: 'deposit first', severity: 'high', points: 20 },
            { text: 'password', severity: 'high', points: 15 },
            { text: 'otp', severity: 'high', points: 20 },
            { text: 'pin', severity: 'high', points: 15 },
            { text: 'cvv', severity: 'high', points: 15 },
            { text: 'security code', severity: 'high', points: 15 },
            { text: 'guaranteed profit', severity: 'high', points: 20 },
            { text: 'free prize', severity: 'medium', points: 10 },
            { text: 'unrealistic discount', severity: 'medium', points: 10 }
        ];

        // Simulate random detection for demo
        commonIndicators.forEach(indicator => {
            if (Math.random() > 0.7) { // 30% chance of detection for demo
                indicators.push({
                    type: indicator.text,
                    severity: indicator.severity,
                    description: `Detected "${indicator.text}" - potential scam indicator`
                });
                score += indicator.points;
            }
        });

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

        return {
            score: score,
            riskLevel: riskLevel,
            indicators: indicators,
            type: type,
            hasOCR: false // OCR not implemented in demo version
        };
    }

    function getTypeSpecificIndicators(type) {
        const typeIndicators = {
            'website': [
                { type: 'Suspicious login form', severity: 'medium', description: 'Login form detected - verify domain carefully' },
                { type: 'Missing HTTPS indicator', severity: 'medium', description: 'No visible HTTPS - proceed with caution' }
            ],
            'payment': [
                { type: 'Payment request detected', severity: 'high', description: 'Payment screen - verify recipient independently' },
                { type: 'Urgency language', severity: 'high', description: 'Urgent payment language detected' }
            ],
            'message': [
                { type: 'Suspicious message format', severity: 'medium', description: 'Message format detected - verify sender' },
                { type: 'Request for personal info', severity: 'high', description: 'Request for personal information detected' }
            ],
            'email': [
                { type: 'Email format detected', severity: 'medium', description: 'Email content - verify sender address' },
                { type: 'Suspicious links', severity: 'high', description: 'Links detected - verify before clicking' }
            ],
            'shopping': [
                { type: 'Shopping interface', severity: 'medium', description: 'Shopping page - verify store legitimacy' },
                { type: 'Discount offers', severity: 'medium', description: 'Discount language detected - verify if realistic' }
            ],
            'social': [
                { type: 'Social media message', severity: 'medium', description: 'Social media content - verify account' },
                { type: 'Verification request', severity: 'high', description: 'Account verification request - verify through official app' }
            ],
            'login': [
                { type: 'Login page detected', severity: 'high', description: 'Login form - verify URL and domain carefully' },
                { type: 'Credential request', severity: 'high', description: 'Requests for login credentials' }
            ],
            'investment': [
                { type: 'Investment offer', severity: 'high', description: 'Investment opportunity - verify through official channels' },
                { type: 'Guaranteed returns', severity: 'high', description: 'Guaranteed return claims - often unrealistic' }
            ],
            'other': [
                { type: 'Suspicious content', severity: 'medium', description: 'Suspicious content detected - verify independently' }
            ]
        };

        return typeIndicators[type] || typeIndicators['other'];
    }

    function displayScreenshotResults(analysis) {
        // Display in scanner result
        if (scannerResult) {
            const warnings = analysis.indicators.map(ind => 
                `⚠ ${ind.description}`
            );
            
            scannerResult.innerHTML = CyberSathiUtils.createSecurityAnalysis(
                analysis.score,
                analysis.riskLevel,
                warnings,
                'Screenshot analysis cannot definitively prove content is fake or malicious. Verify information independently through official channels.'
            );
        }

        // Display detailed analysis
        if (screenshotAnalysisResult) {
            CyberSathiUtils.show(screenshotAnalysisResult);
            
            document.getElementById('screenshot-security-analysis').innerHTML = CyberSathiUtils.createSecurityAnalysis(
                analysis.score,
                analysis.riskLevel,
                analysis.indicators.map(ind => `⚠ ${ind.description}`),
                'This analysis is based on visual patterns and simulated text detection. Always verify independently.'
            );
        }

        // Display detected indicators
        if (detectedIndicators) {
            CyberSathiUtils.show(detectedIndicators);
            
            const indicatorsGrid = document.getElementById('indicators-grid');
            indicatorsGrid.innerHTML = analysis.indicators.map(ind => `
                <div class="indicator-card ${ind.severity === 'high' ? 'warning' : ''}">
                    <h4>${ind.type}</h4>
                    <p>${ind.description}</p>
                </div>
            `).join('');
        }

        // Display action guide
        if (screenshotActionGuide) {
            CyberSathiUtils.show(screenshotActionGuide);
            
            const steps = [
                'Do not take action based solely on this screenshot',
                'Verify all information through official channels',
                'If it\'s a payment request, contact the payee directly',
                'If it\'s a login page, navigate to the official website',
                'Be suspicious of urgency and threats',
                'Report suspicious content to relevant platforms'
            ];
            
            document.getElementById('screenshot-action-steps').innerHTML = CyberSathiUtils.createActionGuide(steps);
        }
    }
});

// OCR-ready function for future implementation
async function extractScreenshotText(image) {
    // OCR integration can be added here later
    // Possible libraries:
    // - Tesseract.js (browser-based OCR)
    // - Google Cloud Vision API
    // - Azure Computer Vision API
    // - AWS Textract
    
    /*
     * Example Tesseract.js implementation:
     * 
     * import Tesseract from 'tesseract.js';
     * 
     * async function extractScreenshotText(image) {
     *     const result = await Tesseract.recognize(image, 'eng');
     *     return result.data.text;
     * }
     */
    
    console.log('OCR integration placeholder - to be implemented');
    return '';
}

// Future API integration placeholder
/*
 * FUTURE API INTEGRATION
 * 
 * This section is reserved for future integration with image analysis APIs.
 * 
 * Possible integrations:
 * - Tesseract.js for local OCR
 * - Google Cloud Vision API for text extraction
 * - Azure Computer Vision for image analysis
 * - Custom ML models for scam pattern recognition
 * 
 * IMPORTANT: For privacy, prefer local processing when possible.
 * If using cloud APIs, obtain proper user consent and explain data usage.
 */