<?php
/**
 * CYBERGUARD AI - Authentication
 */

// Prevent direct access
if (!defined('CYBERGUARD_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/../config/config.php';

class Auth {
    
    /**
     * Check if user is logged in
     */
    public static function check() {
        return isset($_SESSION['user_id']) && isset($_SESSION['role']);
    }
    
    /**
     * Get current user ID
     */
    public static function id() {
        return $_SESSION['user_id'] ?? null;
    }
    
    /**
     * Get current user role
     */
    public static function role() {
        return $_SESSION['role'] ?? null;
    }
    
    /**
     * Get current user data
     */
    public static function user() {
        if (!self::check()) {
            return null;
        }
        return [
            'id' => $_SESSION['user_id'],
            'name' => $_SESSION['name'] ?? '',
            'email' => $_SESSION['email'] ?? '',
            'role' => $_SESSION['role'] ?? ''
        ];
    }
    
    /**
     * Login user
     */
    public static function login($user) {
        session_regenerate_id(true);
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['name'] = $user['name'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['role'] = $user['role'];
        
        // Update last login
        try {
            $db = getDB();
            $stmt = $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $stmt->execute([$user['id']]);
        } catch (Exception $e) {
            error_log('Failed to update last login: ' . $e->getMessage());
        }
        
        // Log the login
        self::logAction(ACTION_LOGIN, 'User logged in');
    }
    
    /**
     * Logout user
     */
    public static function logout() {
        if (self::check()) {
            self::logAction(ACTION_LOGOUT, 'User logged out');
        }
        
        $_SESSION = [];
        
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        
        session_destroy();
    }
    
    /**
     * Require authentication
     */
    public static function require() {
        if (!self::check()) {
            header('Location: /login.php');
            exit;
        }
    }
    
    /**
     * Log user action
     */
    public static function logAction($action, $description = '') {
        try {
            $db = getDB();
            $stmt = $db->prepare("
                INSERT INTO system_logs (user_id, action, description, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                self::id(),
                $action,
                $description,
                self::getClientIP(),
                $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
            ]);
        } catch (Exception $e) {
            error_log('Failed to log action: ' . $e->getMessage());
        }
    }
    
    /**
     * Get client IP address
     */
    private static function getClientIP() {
        $ip = '';
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }
}

// Helper functions
function is_logged_in() {
    return Auth::check();
}

function current_user() {
    return Auth::user();
}

function require_login() {
    Auth::require();
}
