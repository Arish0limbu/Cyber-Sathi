// Cyber Sathi - Data Loader JavaScript

// Demo threat data - This is sample data for demonstration purposes
// In a production environment, this would be loaded from an external API
const demoThreatData = {
    metadata: {
        version: "1.0.0",
        lastUpdated: "2024-01-01",
        disclaimer: "This is demo threat intelligence data for educational purposes only. It is not a live global threat database.",
        dataSources: "Educational examples and common scam patterns"
    },
    
    suspiciousDomains: [
        {
            domain: "example-scam.com",
            risk: "high",
            type: "phishing",
            description: "Known phishing domain targeting financial services"
        },
        {
            domain: "fake-login.net",
            risk: "high", 
            type: "credential_harvesting",
            description: "Credential harvesting site"
        },
        {
            domain: "suspicious-shop.org",
            risk: "medium",
            type: "fake_store",
            description: "Suspicious online store with multiple complaints"
        },
        {
            domain: "investment-scam.io",
            risk: "high",
            type: "investment_fraud",
            description: "Fraudulent investment platform"
        }
    ],
    
    suspiciousPatterns: [
        {
            pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
            risk: "medium",
            type: "ip_url",
            description: "IP-based URL instead of domain name"
        },
        {
            pattern: /xn--/,
            risk: "medium",
            type: "punycode",
            description: "Punycode domain (possible homograph attack)"
        },
        {
            pattern: /@/,
            risk: "medium",
            type: "username_in_url",
            description: "Username in URL (possible credential theft)"
        },
        {
            pattern: /\.\./,
            risk: "high",
            type: "directory_traversal",
            description: "Directory traversal attempt"
        }
    ],
    
    scamKeywords: {
        urgency: [
            "act now", "immediate action", "right now", "last chance",
            "limited time", "expires soon", "don't wait", "hurry",
            "urgent", "emergency", "critical", "time sensitive"
        ],
        threats: [
            "account will be closed", "account suspended", "legal action",
            "arrest warrant", "police", "court", "fine", "penalty",
            "lawsuit", "investigation", "fraud department"
        ],
        financial: [
            "send money", "pay fee", "deposit", "wire transfer",
            "bank account", "credit card", "payment", "invest",
            "loan", "cryptocurrency", "bitcoin", "wallet"
        ],
        credentials: [
            "password", "otp", "pin", "cvv", "security code",
            "login details", "verify account", "confirm identity",
            "authentication", "credentials"
        ],
        prizes: [
            "won", "lottery", "prize", "free", "bonus",
            "reward", "gift", "congratulations", "winner",
            "claim now", "cash prize"
        ],
        jobs: [
            "job offer", "work from home", "earn money", "guaranteed income",
            "investment opportunity", "high returns", "profit",
            "crypto investment", "trading", "passive income"
        ]
    },
    
    phishingPatterns: [
        {
            pattern: /login|signin|verify|account|secure|bank/i,
            risk: "medium",
            description: "Common phishing-related keywords"
        },
        {
            pattern: /update|confirm|validate|authenticate/i,
            risk: "medium", 
            description: "Action-oriented phishing keywords"
        },
        {
            pattern: /wallet|crypto|bitcoin|blockchain/i,
            risk: "medium",
            description: "Cryptocurrency-related phishing patterns"
        }
    ],
    
    redFlags: {
        payment: [
            "Requests for OTP/PIN sharing",
            "Urgent payment demands",
            "Requests to share banking credentials",
            "Payment to unknown recipients",
            "Requests for advance fees"
        ],
        qr: [
            "QR codes from unknown sources",
            "QR codes in unsolicited messages",
            "Payment QR codes without verification",
            "QR codes promising unrealistic rewards"
        ],
        messages: [
            "Unsolicited messages requesting action",
            "Messages creating false urgency",
            "Requests for sensitive information",
            "Threats or intimidation",
            "Too-good-to-be-true offers"
        ],
        shopping: [
            "Unrealistically low prices",
            "Pressure to buy quickly",
            "Requests for unusual payment methods",
            "Lack of contact information",
            "Poor website design"
        ]
    },
    
    safeDomains: [
        "google.com",
        "facebook.com", 
        "amazon.com",
        "apple.com",
        "microsoft.com",
        "paypal.com"
    ]
};

// Data loader class
class ThreatDataLoader {
    constructor() {
        this.data = null;
        this.loaded = false;
    }

    // Load threat data (in this case, from the embedded demo data)
    async loadThreatData() {
        try {
            // In a real implementation, this would fetch from an external JSON file
            // const response = await fetch('data/threats.json');
            // this.data = await response.json();
            
            // For demo purposes, use embedded data
            this.data = demoThreatData;
            this.loaded = true;
            
            console.log('Threat data loaded successfully');
            console.log('Data sources:', this.data.metadata.dataSources);
            console.log('Disclaimer:', this.data.metadata.disclaimer);
            
            return this.data;
        } catch (error) {
            console.error('Error loading threat data:', error);
            // Return demo data as fallback
            this.data = demoThreatData;
            this.loaded = true;
            return this.data;
        }
    }

    // Check if a domain is in the suspicious list
    isSuspiciousDomain(domain) {
        if (!this.loaded) {
            console.warn('Threat data not loaded, call loadThreatData() first');
            return false;
        }

        const lowerDomain = domain.toLowerCase();
        return this.data.suspiciousDomains.some(item => 
            lowerDomain.includes(item.domain.toLowerCase())
        );
    }

    // Get domain risk level
    getDomainRisk(domain) {
        if (!this.loaded) {
            return null;
        }

        const lowerDomain = domain.toLowerCase();
        const match = this.data.suspiciousDomains.find(item => 
            lowerDomain.includes(item.domain.toLowerCase())
        );

        return match ? match : null;
    }

    // Check for suspicious patterns in text
    checkSuspiciousPatterns(text) {
        if (!this.loaded) {
            return [];
        }

        const findings = [];
        
        this.data.suspiciousPatterns.forEach(pattern => {
            if (pattern.pattern.test(text)) {
                findings.push({
                    type: pattern.type,
                    risk: pattern.risk,
                    description: pattern.description
                });
            }
        });

        return findings;
    }

    // Check for scam keywords in text
    checkScamKeywords(text) {
        if (!this.loaded) {
            return [];
        }

        const findings = [];
        const lowerText = text.toLowerCase();

        Object.keys(this.data.scamKeywords).forEach(category => {
            this.data.scamKeywords[category].forEach(keyword => {
                if (lowerText.includes(keyword.toLowerCase())) {
                    findings.push({
                        category: category,
                        keyword: keyword,
                        severity: this.getKeywordSeverity(category)
                    });
                }
            });
        });

        return findings;
    }

    // Get severity level for keyword category
    getKeywordSeverity(category) {
        const severityMap = {
            'urgency': 'high',
            'threats': 'high',
            'financial': 'high',
            'credentials': 'high',
            'prizes': 'medium',
            'jobs': 'high'
        };
        return severityMap[category] || 'medium';
    }

    // Check if domain is in safe list
    isSafeDomain(domain) {
        if (!this.loaded) {
            return false;
        }

        const lowerDomain = domain.toLowerCase();
        return this.data.safeDomains.some(safe => 
            lowerDomain.endsWith(safe.toLowerCase())
        );
    }

    // Get red flags for a category
    getRedFlags(category) {
        if (!this.loaded) {
            return [];
        }

        return this.data.redFlags[category] || [];
    }

    // Get phishing pattern matches
    checkPhishingPatterns(text) {
        if (!this.loaded) {
            return [];
        }

        const findings = [];
        
        this.data.phishingPatterns.forEach(pattern => {
            if (pattern.pattern.test(text)) {
                findings.push({
                    risk: pattern.risk,
                    description: pattern.description
                });
            }
        });

        return findings;
    }

    // Get data metadata
    getMetadata() {
        if (!this.loaded) {
            return null;
        }
        return this.data.metadata;
    }
}

// Create global instance
const threatDataLoader = new ThreatDataLoader();

// Auto-load data when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    threatDataLoader.loadThreatData();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ThreatDataLoader, threatDataLoader, demoThreatData };
}