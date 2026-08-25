// Cyber Sathi - Message Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');
    const analyzeMessageBtn = document.getElementById('analyze-message-btn');
    const scannerResult = document.getElementById('scanner-result');
    const messageAnalysisResult = document.getElementById('message-analysis-result');
    const detectedPatterns = document.getElementById('detected-patterns');
    const messageActionGuide = document.getElementById('message-action-guide');

    // Message form submission
    if (messageForm) {
        messageForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const message = messageInput.value.trim();
            const messageType = document.getElementById('message-type').value;
            
            if (message) {
                analyzeMessage(message, messageType);
            } else {
                CyberSathiUtils.showToast('Please enter a message to analyze', 'error');
            }
        });
    }

    function analyzeMessage(message, type) {
        // Show loading state
        if (analyzeMessageBtn) {
            CyberSathiUtils.showLoading(analyzeMessageBtn);
        }

        // Simulate analysis
        setTimeout(() => {
            const analysis = performMessageAnalysis(message, type);
            displayMessageResults(analysis);

            // Hide loading state
            if (analyzeMessageBtn) {
                CyberSathiUtils.hideLoading(analyzeMessageBtn);
            }
        }, 1500);
    }

    function performMessageAnalysis(message, type) {
        const patterns = [];
        let score = 0;
        const lowerMessage = message.toLowerCase();

        // Urgency indicators
        const urgencyPatterns = [
            { pattern: 'act now', points: 15, description: 'Urgency language detected' },
            { pattern: 'immediate action', points: 15, description: 'Immediate action requested' },
            { pattern: 'right now', points: 10, description: 'Time-sensitive language' },
            { pattern: 'last chance', points: 15, description: 'Last chance warning' },
            { pattern: 'limited time', points: 10, description: 'Limited time offer' },
            { pattern: 'expires soon', points: 10, description: 'Expiration urgency' },
            { pattern: 'don\'t wait', points: 10, description: 'Urgency to act quickly' },
            { pattern: 'hurry', points: 10, description: 'Hurrying language' }
        ];

        urgencyPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Urgency',
                    severity: 'high',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Threat indicators
        const threatPatterns = [
            { pattern: 'account will be closed', points: 20, description: 'Account closure threat' },
            { pattern: 'account suspended', points: 20, description: 'Account suspension threat' },
            { pattern: 'legal action', points: 25, description: 'Legal action threat' },
            { pattern: 'arrest warrant', points: 25, description: 'Arrest threat' },
            { pattern: 'police', points: 15, description: 'Police reference' },
            { pattern: 'court', points: 15, description: 'Legal action reference' },
            { pattern: 'fine', points: 15, description: 'Fine threat' },
            { pattern: 'penalty', points: 15, description: 'Penalty threat' }
        ];

        threatPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Threat',
                    severity: 'high',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Financial request indicators
        const financialPatterns = [
            { pattern: 'send money', points: 20, description: 'Money transfer request' },
            { pattern: 'pay fee', points: 15, description: 'Fee payment request' },
            { pattern: 'deposit', points: 15, description: 'Deposit request' },
            { pattern: 'wire transfer', points: 20, description: 'Wire transfer request' },
            { pattern: 'bank account', points: 15, description: 'Bank account request' },
            { pattern: 'credit card', points: 15, description: 'Credit card request' },
            { pattern: 'payment', points: 10, description: 'Payment request' },
            { pattern: 'invest', points: 15, description: 'Investment request' },
            { pattern: 'loan', points: 15, description: 'Loan offer' }
        ];

        financialPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Financial Request',
                    severity: 'high',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Credential request indicators
        const credentialPatterns = [
            { pattern: 'password', points: 20, description: 'Password request' },
            { pattern: 'otp', points: 25, description: 'OTP request' },
            { pattern: 'pin', points: 20, description: 'PIN request' },
            { pattern: 'cvv', points: 20, description: 'CVV request' },
            { pattern: 'security code', points: 20, description: 'Security code request' },
            { pattern: 'login details', points: 15, description: 'Login details request' },
            { pattern: 'verify account', points: 15, description: 'Account verification request' },
            { pattern: 'confirm identity', points: 15, description: 'Identity confirmation request' }
        ];

        credentialPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Credential Request',
                    severity: 'high',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Suspicious link indicators
        const linkPatterns = [
            { pattern: 'http://', points: 10, description: 'Unsecured link' },
            { pattern: 'bit.ly', points: 15, description: 'URL shortener' },
            { pattern: 'tinyurl', points: 15, description: 'URL shortener' },
            { pattern: 'click here', points: 10, description: 'Generic click instruction' },
            { pattern: 'link', points: 5, description: 'Link reference' },
            { pattern: 'verify', points: 10, description: 'Verification link' }
        ];

        linkPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Suspicious Link',
                    severity: 'medium',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Fake prize/offer indicators
        const prizePatterns = [
            { pattern: 'won', points: 15, description: 'Prize winning claim' },
            { pattern: 'lottery', points: 15, description: 'Lottery reference' },
            { pattern: 'prize', points: 15, description: 'Prize offer' },
            { pattern: 'free', points: 10, description: 'Free offer' },
            { pattern: 'bonus', points: 10, description: 'Bonus offer' },
            { pattern: 'reward', points: 10, description: 'Reward offer' },
            { pattern: 'gift', points: 10, description: 'Gift offer' },
            { pattern: 'congratulations', points: 10, description: 'Congratulations message' }
        ];

        prizePatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Fake Prize/Offer',
                    severity: 'medium',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Job/investment scam indicators
        const jobPatterns = [
            { pattern: 'job offer', points: 15, description: 'Job offer' },
            { pattern: 'work from home', points: 10, description: 'Work from home offer' },
            { pattern: 'earn money', points: 15, description: 'Earning claim' },
            { pattern: 'guaranteed income', points: 20, description: 'Guaranteed income claim' },
            { pattern: 'investment opportunity', points: 15, description: 'Investment offer' },
            { pattern: 'high returns', points: 20, description: 'High return claim' },
            { pattern: 'profit', points: 15, description: 'Profit claim' },
            { pattern: 'crypto', points: 15, description: 'Cryptocurrency reference' }
        ];

        jobPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Job/Investment Scam',
                    severity: 'high',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
            }
        });

        // Impersonation indicators
        const impersonationPatterns = [
            { pattern: 'amazon', points: 10, description: 'Brand impersonation' },
            { pattern: 'google', points: 10, description: 'Brand impersonation' },
            { pattern: 'microsoft', points: 10, description: 'Brand impersonation' },
            { pattern: 'apple', points: 10, description: 'Brand impersonation' },
            { pattern: 'facebook', points: 10, description: 'Brand impersonation' },
            { pattern: 'bank', points: 15, description: 'Bank impersonation' },
            { pattern: 'support', points: 10, description: 'Support claim' },
            { pattern: 'customer service', points: 10, description: 'Customer service claim' }
        ];

        impersonationPatterns.forEach(item => {
            if (lowerMessage.includes(item.pattern)) {
                patterns.push({
                    type: 'Impersonation',
                    severity: 'medium',
                    pattern: item.pattern,
                    description: item.description
                });
                score += item.points;
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

        // Generate recommendation
        let recommendation;
        if (score <= 20) {
            recommendation = 'This message shows few suspicious indicators. However, always verify the sender independently before taking any action.';
        } else if (score <= 40) {
            recommendation = 'This message contains some suspicious elements. Verify the sender through official channels and do not click on links or share information.';
        } else if (score <= 60) {
            recommendation = 'This message shows multiple scam indicators. Do not click links, share information, or take any action. Verify through official channels.';
        } else if (score <= 80) {
            recommendation = 'This message exhibits high-risk scam characteristics. Do not respond, click links, or share any information. Report and block the sender.';
        } else {
            recommendation = 'This message shows very high-risk scam indicators. Do not interact with it. Report to relevant platforms and authorities if appropriate.';
        }

        return {
            score: score,
            riskLevel: riskLevel,
            patterns: patterns,
            messageType: type,
            recommendation: recommendation
        };
    }

    function displayMessageResults(analysis) {
        // Display in scanner result
        if (scannerResult) {
            const warnings = analysis.patterns.map(pattern => 
                `⚠ ${pattern.description} (${pattern.type})`
            );
            
            scannerResult.innerHTML = CyberSathiUtils.createSecurityAnalysis(
                analysis.score,
                analysis.riskLevel,
                warnings,
                analysis.recommendation
            );
        }

        // Display detailed analysis
        if (messageAnalysisResult) {
            CyberSathiUtils.show(messageAnalysisResult);
            
            document.getElementById('message-security-analysis').innerHTML = CyberSathiUtils.createSecurityAnalysis(
                analysis.score,
                analysis.riskLevel,
                analysis.patterns.map(pattern => `⚠ ${pattern.description}`),
                analysis.recommendation
            );
        }

        // Display detected patterns
        if (detectedPatterns) {
            CyberSathiUtils.show(detectedPatterns);
            
            const patternsGrid = document.getElementById('patterns-grid');
            patternsGrid.innerHTML = analysis.patterns.map(pattern => `
                <div class="pattern-card ${pattern.severity === 'high' ? 'warning' : ''}">
                    <h4>${pattern.type}</h4>
                    <p><strong>Pattern:</strong> "${pattern.pattern}"</p>
                    <p>${pattern.description}</p>
                </div>
            `).join('');
        }

        // Display action guide
        if (messageActionGuide) {
            CyberSathiUtils.show(messageActionGuide);
            
            const steps = getMessageActionSteps(analysis.riskLevel, analysis.patterns);
            document.getElementById('message-action-steps').innerHTML = CyberSathiUtils.createActionGuide(steps);
        }
    }

    function getMessageActionSteps(riskLevel, patterns) {
        const baseSteps = [
            'Do not click on any links in the message',
            'Do not reply to the message',
            'Do not share any personal information'
        ];

        const hasCredentialRequest = patterns.some(p => p.type === 'Credential Request');
        const hasFinancialRequest = patterns.some(p => p.type === 'Financial Request');
        const hasThreat = patterns.some(p => p.type === 'Threat');

        let specificSteps = [];
        
        if (hasCredentialRequest) {
            specificSteps.push('Never share OTPs, PINs, or passwords');
        }
        
        if (hasFinancialRequest) {
            specificSteps.push('Do not send money or make payments');
        }
        
        if (hasThreat) {
            specificSteps.push('Legitimate organizations don\'t make threats via message');
        }

        if (riskLevel === 'HIGH RISK' || riskLevel === 'VERY HIGH RISK') {
            return [
                ...baseSteps,
                ...specificSteps,
                'Report the message to the platform (spam, scam report)',
                'Block the sender',
                'Contact the organization through official channels if you\'re concerned'
            ];
        } else {
            return [
                ...baseSteps,
                ...specificSteps,
                'Verify the sender through official channels',
                'Contact the organization directly if you\'re unsure'
            ];
        }
    }
});

// Future API integration placeholder
/*
 * FUTURE API INTEGRATION
 * 
 * This section is reserved for future integration with message analysis APIs.
 * 
 * Possible integrations:
 * - Natural Language Processing APIs for sentiment analysis
 * - Machine learning models for scam detection
 * - Real-time threat intelligence feeds
 * - SMS/email filtering APIs
 * 
 * IMPORTANT: Message content may contain sensitive information.
 * If using cloud APIs, ensure proper data protection and user consent.
 */