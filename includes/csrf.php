<?php
/**
 * CYBERGUARD AI - CSRF Protection
 */

// Prevent direct access
if (!defined('CYBERGUARD_ACCESS')) {
    die('Direct access not permitted');
}

class CSRFProtection {
    
    /**
     * Generate CSRF token
     */
    public static function generateToken() {
        if (!isset($_SESSION[CSRF_TOKEN_NAME])) {
            $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        }
        return $_SESSION[CSRF_TOKEN_NAME];
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateToken($token) {
        if (!isset($_SESSION[CSRF_TOKEN_NAME])) {
            return false;
        }
        return hash_equals($_SESSION[CSRF_TOKEN_NAME], $token);
    }
    
    /**
     * Get CSRF token for forms
     */
    public static function getToken() {
        return self::generateToken();
    }
    
    /**
     * Regenerate CSRF token
     */
    public static function regenerateToken() {
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        return $_SESSION[CSRF_TOKEN_NAME];
    }
    
    /**
     * Validate request (POST)
     */
    public static function validateRequest() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST[CSRF_TOKEN_NAME] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!self::validateToken($token)) {
                http_response_code(403);
                die('CSRF token validation failed');
            }
        }
    }
}

// Helper function for quick access
function csrf_token() {
    return CSRFProtection::getToken();
}

function csrf_field() {
    return '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . csrf_token() . '">';
}
