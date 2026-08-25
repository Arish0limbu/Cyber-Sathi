<?php
/**
 * CYBERGUARD AI - Admin Authentication
 */

// Prevent direct access
if (!defined('CYBERGUARD_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/auth.php';

class AdminAuth {
    
    /**
     * Check if user is admin
     */
    public static function check() {
        return Auth::check() && Auth::role() === ROLE_ADMIN;
    }
    
    /**
     * Require admin authentication
     */
    public static function require() {
        Auth::require();
        
        if (!self::check()) {
            header('Location: /dashboard.php');
            exit;
        }
    }
    
    /**
     * Check if user has specific permission
     */
    public static function hasPermission($permission) {
        if (!self::check()) {
            return false;
        }
        
        // Admins have all permissions
        return true;
    }
}

// Helper function
function require_admin() {
    AdminAuth::require();
}

function is_admin() {
    return AdminAuth::check();
}
