<?php
/**
 * CYBERGUARD AI - Permissions System
 */

// Prevent direct access
if (!defined('CYBERGUARD_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/auth.php';

class Permissions {
    
    /**
     * Check if user can view scan
     */
    public static function canViewScan($scanId, $userId = null) {
        if (is_admin()) {
            return true;
        }
        
        $userId = $userId ?? Auth::id();
        
        try {
            $db = getDB();
            $stmt = $db->prepare("SELECT user_id FROM scans WHERE id = ?");
            $stmt->execute([$scanId]);
            $scan = $stmt->fetch();
            
            return $scan && $scan['user_id'] == $userId;
        } catch (Exception $e) {
            error_log('Permission check failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user can delete scan
     */
    public static function canDeleteScan($scanId, $userId = null) {
        return self::canViewScan($scanId, $userId);
    }
    
    /**
     * Check if user can view report
     */
    public static function canViewReport($reportId, $userId = null) {
        if (is_admin()) {
            return true;
        }
        
        $userId = $userId ?? Auth::id();
        
        try {
            $db = getDB();
            $stmt = $db->prepare("SELECT user_id FROM reports WHERE id = ?");
            $stmt->execute([$reportId]);
            $report = $stmt->fetch();
            
            return $report && $report['user_id'] == $userId;
        } catch (Exception $e) {
            error_log('Permission check failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user can manage users (admin only)
     */
    public static function canManageUsers() {
        return is_admin();
    }
    
    /**
     * Check if user can view system logs (admin only)
     */
    public static function canViewSystemLogs() {
        return is_admin();
    }
    
    /**
     * Check if user can manage API settings (admin only)
     */
    public static function canManageApiSettings() {
        return is_admin();
    }
    
    /**
     * Check if user can view threat intelligence
     */
    public static function canViewThreatIntelligence() {
        return is_logged_in();
    }
    
    /**
     * Check if user can use scanner
     */
    public static function canUseScanner() {
        return is_logged_in();
    }
    
    /**
     * Check if user can generate reports
     */
    public static function canGenerateReports() {
        return is_logged_in();
    }
}

// Helper functions
function can_view_scan($scanId) {
    return Permissions::canViewScan($scanId);
}

function can_delete_scan($scanId) {
    return Permissions::canDeleteScan($scanId);
}

function can_manage_users() {
    return Permissions::canManageUsers();
}

function can_view_system_logs() {
    return Permissions::canViewSystemLogs();
}
