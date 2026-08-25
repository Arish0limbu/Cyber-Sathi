<?php
/**
 * CYBERGUARD AI - Main Configuration
 */

// Security constant
define('CYBERGUARD_ACCESS', true);

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'cyberguard_ai');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');

// Application Settings
define('APP_NAME', 'CYBERGUARD AI');
define('APP_URL', 'https://yourdomain.com');
define('APP_VERSION', '1.0.0');

// Demo Mode
// When true, external APIs are disabled and internal demo analysis is used
define('DEMO_MODE', true);

// Security Settings
define('CSRF_TOKEN_NAME', 'csrf_token');
define('SESSION_LIFETIME', 3600); // 1 hour
define('REMEMBER_ME_LIFETIME', 2592000); // 30 days

// Rate Limiting
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_LOGIN', 5); // 5 attempts per minute
define('RATE_LIMIT_REGISTER', 3); // 3 attempts per minute
define('RATE_LIMIT_SCAN', 10); // 10 scans per minute
define('RATE_LIMIT_API', 60); // 60 API calls per minute

// File Upload Settings
define('MAX_FILE_SIZE', 5242880); // 5MB in bytes
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
define('ALLOWED_FILE_TYPES', ['text/plain', 'application/pdf']);

// Risk Thresholds
define('RISK_SAFE', 19);
define('RISK_LOW', 39);
define('RISK_MEDIUM', 59);
define('RISK_HIGH', 79);

// Timezone
date_default_timezone_set('UTC');

// Error Reporting (Production: 0, Development: E_ALL)
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/php_errors.log');

// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Content Security Policy (Basic - adjust as needed)
// header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net;");

// Include other config files
require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/api-config.php';
