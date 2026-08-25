// Cyber Sathi - QR Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const qrUploadForm = document.getElementById('qr-upload-form');
    const qrFileInput = document.getElementById('qr-file-input');
    const analyzeQrBtn = document.getElementById('analyze-qr-btn');
    const cameraBtn = document.getElementById('camera-btn');
    const cameraContainer = document.getElementById('camera-container');
    const cameraFeed = document.getElementById('camera-feed');
    const captureBtn = document.getElementById('capture-btn');
    const stopCameraBtn = document.getElementById('stop-camera-btn');
    const scannerResult = document.getElementById('scanner-result');
    const qrAnalysisResult = document.getElementById('qr-analysis-result');
    const qrActionGuide = document.getElementById('qr-action-guide');

    let cameraStream = null;

    // File upload handling
    if (qrFileInput) {
        qrFileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const preview = document.getElementById('file-preview');
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    preview.innerHTML = `<img src="${e.target.result}" alt="QR Code Preview">`;
                };
                
                reader.readAsDataURL(file);
            }
        });
    }

    // QR upload form submission
    if (qrUploadForm) {
        qrUploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const file = qrFileInput.files[0];
            if (file) {
                analyzeQrCode(file);
            } else {
                CyberSathiUtils.showToast('Please select a QR code image', 'error');
            }
        });
    }

    // Camera handling
    if (cameraBtn) {
        cameraBtn.addEventListener('click', function() {
            startCamera();
        });
    }

    if (stopCameraBtn) {
        stopCameraBtn.addEventListener('click', function() {
            stopCamera();
        });
    }

    if (captureBtn) {
        captureBtn.addEventListener('click', function() {
            captureQrCode();
        });
    }

    // Payment scam form
    const paymentScamForm = document.getElementById('payment-scam-form');
    if (paymentScamForm) {
        paymentScamForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const paymentFileInput = document.getElementById('payment-file-input');
            const file = paymentFileInput.files[0];
            if (file) {
                analyzePaymentScam(file);
            } else {
                CyberSathiUtils.showToast('Please select a payment screenshot', 'error');
            }
        });

        // Handle payment file preview
        const paymentFileInput = document.getElementById('payment-file-input');
        if (paymentFileInput) {
            paymentFileInput.addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file) {
                    const preview = document.getElementById('payment-preview');
                    const reader = new FileReader();
                    
                    reader.onload = function(e) {
                        preview.innerHTML = `<img src="${e.target.result}" alt="Payment Screenshot Preview">`;
                    };
                    
                    reader.readAsDataURL(file);
                }
            });
        }
    }

    async function startCamera() {
        try {
            cameraStream = await navigator.mediaDevices.getUserMedia({ 
                video: { facingMode: 'environment' } 
            });
            
            if (cameraFeed) {
                cameraFeed.srcObject = cameraStream;
                cameraFeed.play();
            }
            
            CyberSathiUtils.show(cameraContainer);
            CyberSathiUtils.hide(cameraBtn);
            
        } catch (err) {
            console.error('Camera access error:', err);
            CyberSathiUtils.showToast('Unable to access camera. Please check permissions.', 'error');
        }
    }

    function stopCamera() {
        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
            cameraStream = null;
        }
        
        CyberSathiUtils.hide(cameraContainer);
        CyberSathiUtils.show(cameraBtn);
    }

    function captureQrCode() {
        if (!cameraFeed || !cameraStream) {
            CyberSathiUtils.showToast('Camera not active', 'error');
            return;
        }

        const canvas = document.getElementById('camera-canvas');
        if (canvas) {
            canvas.width = cameraFeed.videoWidth;
            canvas.height = cameraFeed.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(cameraFeed, 0, 0);
            
            // Convert to blob and analyze
            canvas.toBlob(function(blob) {
                analyzeQrCode(blob);
                stopCamera();
            }, 'image/png');
        }
    }

    function analyzeQrCode(file) {
        // Show loading state
        if (analyzeQrBtn) {
            CyberSathiUtils.showLoading(analyzeQrBtn);
        }

        // Simulate QR code analysis
        setTimeout(() => {
            // In a real implementation, this would use a QR code decoding library
            // For demo purposes, we'll simulate decoding
            const simulatedDestination = simulateQrDecoding(file);
            
            // Analyze the decoded URL using the URL scanner logic
            const urlAnalysis = performUrlAnalysis(simulatedDestination);
            
            displayQrResults(simulatedDestination, urlAnalysis);

            // Hide loading state
            if (analyzeQrBtn) {
                CyberSathiUtils.hideLoading(analyzeQrBtn);
            }
        }, 2000);
    }

    function simulateQrDecoding(file) {
        // In a real implementation, this would use a library like jsQR
        // For demo purposes, we'll return a simulated destination
        const destinations = [
            'https://example.com/payment',
            'https://secure-login.example.com/account',
            'http://suspicious-site.net/verify',
            'https://bit.ly/example',
            'https://example.com'
        ];
        
        // Randomly select one for demo
        return destinations[Math.floor(Math.random() * destinations.length)];
    }

    function performUrlAnalysis(url) {
        // Reuse the URL analysis logic from scanner.js
        const warnings = [];
        let score = 0;
        const domain = CyberSathiUtils.extractDomain(url);

        // Basic checks (simplified version)
        if (!url.startsWith('https://')) {
            warnings.push('⚠ No HTTPS encryption');
            score += 15;
        }

        if (url.includes('payment') || url.includes('login') || url.includes('verify')) {
            warnings.push('⚠ Payment/login-related destination');
            score += 15;
        }

        if (url.includes('bit.ly') || url.includes('tinyurl')) {
            warnings.push('⚠ URL shortener detected (cannot see final destination)');
            score += 20;
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

        return {
            url: url,
            domain: domain,
            score: score,
            riskLevel: riskLevel,
            warnings: warnings
        };
    }

    function displayQrResults(destination, urlAnalysis) {
        // Display in scanner result
        if (scannerResult) {
            scannerResult.innerHTML = CyberSathiUtils.createSecurityAnalysis(
                urlAnalysis.score,
                urlAnalysis.riskLevel,
                urlAnalysis.warnings,
                'Verify the QR code destination independently before interacting with it.'
            );
        }

        // Display QR-specific results
        if (qrAnalysisResult) {
            CyberSathiUtils.show(qrAnalysisResult);
            
            document.getElementById('qr-destination-url').textContent = destination;
            document.getElementById('qr-security-analysis').innerHTML = CyberSathiUtils.createSecurityAnalysis(
                urlAnalysis.score,
                urlAnalysis.riskLevel,
                urlAnalysis.warnings,
                'QR codes can hide malicious URLs. Always verify the destination before taking action.'
            );
        }

        // Display action guide
        if (qrActionGuide) {
            CyberSathiUtils.show(qrActionGuide);
            
            const steps = [
                'Do not interact with the QR code destination without verification',
                'If it\'s a payment QR, verify the recipient independently',
                'If it\'s a login QR, go to the official website directly instead',
                'Be suspicious of QR codes from unknown sources',
                'Report suspicious QR codes to relevant platforms'
            ];
            
            document.getElementById('qr-action-steps').innerHTML = CyberSathiUtils.createActionGuide(steps);
        }
    }

    function analyzePaymentScam(file) {
        const analyzeBtn = document.getElementById('analyze-payment-btn');
        
        // Show loading state
        if (analyzeBtn) {
            CyberSathiUtils.showLoading(analyzeBtn);
        }

        // Simulate analysis
        setTimeout(() => {
            const result = document.getElementById('payment-scam-result');
            if (result) {
                CyberSathiUtils.show(result);
                result.innerHTML = `
                    <div class="security-analysis">
                        <h2>⚠ POTENTIAL PAYMENT SCAM</h2>
                        <div class="warnings-list">
                            <h3>Warning signs detected:</h3>
                            <ul>
                                <li>⚠ Requests sensitive information</li>
                                <li>⚠ Urgent payment language</li>
                                <li>⚠ Destination could not be verified</li>
                            </ul>
                        </div>
                        <div class="recommendation">
                            <h3>Recommendation:</h3>
                            <p>Do not send money or share OTP/PIN until the recipient and payment details are independently verified through official channels.</p>
                        </div>
                    </div>
                `;
            }

            // Hide loading state
            if (analyzeBtn) {
                CyberSathiUtils.hideLoading(analyzeBtn);
            }
        }, 2000);
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
 * This section is reserved for future integration with QR code decoding APIs.
 * 
 * Possible integrations:
 * - Local QR code decoding libraries (jsQR, qr-scanner)
 * - Cloud-based QR decoding APIs
 * - QR code reputation databases
 * 
 * IMPORTANT: For QR code decoding, prefer local libraries to maintain privacy.
 * Only use cloud APIs if necessary and with proper user consent.
 */