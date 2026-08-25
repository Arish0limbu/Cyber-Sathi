<?php
/**
 * CYBERGUARD AI - Helper Functions
 */

// Prevent direct access
if (!defined('CYBERGUARD_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/../config/config.php';

/**
 * Sanitize output
 */
function e($string) {
    return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
}

/**
 * Redirect with optional message
 */
function redirect($url, $message = null, $type = 'info') {
    if ($message) {
        $_SESSION['flash_message'] = $message;
        $_SESSION['flash_type'] = $type;
    }
    header('Location: ' . $url);
    exit;
}

/**
 * Get flash message
 */
function getFlashMessage() {
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        $type = $_SESSION['flash_type'] ?? 'info';
        unset($_SESSION['flash_message']);
        unset($_SESSION['flash_type']);
        return ['message' => $message, 'type' => $type];
    }
    return null;
}

/**
 * Generate random string
 */
function generateRandomString($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

/**
 * Hash API key
 */
function hashApiKey($apiKey) {
    return hash('sha256', $apiKey);
}

/**
 * Validate email
 */
function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate URL
 */
function isValidUrl($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Validate IP address
 */
function isValidIP($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Get risk level from score
 */
function getRiskLevel($score) {
    if ($score <= RISK_SAFE) return RISK_LEVEL_SAFE;
    if ($score <= RISK_LOW) return RISK_LEVEL_LOW;
    if ($score <= RISK_MEDIUM) return RISK_LEVEL_MEDIUM;
    if ($score <= RISK_HIGH) return RISK_LEVEL_HIGH;
    return RISK_LEVEL_CRITICAL;
}

/**
 * Get risk level color
 */
function getRiskLevelColor($level) {
    switch ($level) {
        case RISK_LEVEL_SAFE:
            return '#10B981';
        case RISK_LEVEL_LOW:
            return '#3B82F6';
        case RISK_LEVEL_MEDIUM:
            return '#F59E0B';
        case RISK_LEVEL_HIGH:
            return '#EF4444';
        case RISK_LEVEL_CRITICAL:
            return '#DC2626';
        default:
            return '#6B7280';
    }
}

/**
 * Format date
 */
function formatDate($date, $format = 'Y-m-d H:i:s') {
    if (!$date) return '-';
    $timestamp = strtotime($date);
    return date($format, $timestamp);
}

/**
 * Time ago
 */
function timeAgo($date) {
    if (!$date) return '-';
    
    $timestamp = strtotime($date);
    $now = time();
    $diff = $now - $timestamp;
    
    if ($diff < 60) return 'Just now';
    if ($diff < 3600) return floor($diff / 60) . ' min ago';
    if ($diff < 86400) return floor($diff / 3600) . ' hours ago';
    if ($diff < 604800) return floor($diff / 86400) . ' days ago';
    
    return formatDate($date, 'M d, Y');
}

/**
 * Truncate text
 */
function truncate($text, $length = 100, $suffix = '...') {
    if (strlen($text) <= $length) return $text;
    return substr($text, 0, $length) . $suffix;
}

/**
 * Format file size
 */
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    }
    return $bytes . ' bytes';
}

/**
 * Send JSON response
 */
function jsonResponse($success, $message, $data = null) {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ]);
    exit;
}

/**
 * Send error JSON response
 */
function jsonError($message, $data = null) {
    jsonResponse(false, $message, $data);
}

/**
 * Send success JSON response
 */
function jsonSuccess($message, $data = null) {
    jsonResponse(true, $message, $data);
}

/**
 * Check rate limit
 */
function checkRateLimit($identifier, $action, $limit, $window = 60) {
    if (!RATE_LIMIT_ENABLED) {
        return true;
    }
    
    try {
        $db = getDB();
        
        // Clean old entries
        $stmt = $db->prepare("DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL ? SECOND)");
        $stmt->execute([$window]);
        
        // Check current rate
        $stmt = $db->prepare("
            SELECT request_count, window_start 
            FROM rate_limits 
            WHERE identifier = ? AND action = ?
        ");
        $stmt->execute([$identifier, $action]);
        $result = $stmt->fetch();
        
        if (!$result) {
            // First request
            $stmt = $db->prepare("
                INSERT INTO rate_limits (identifier, action, request_count, window_start)
                VALUES (?, ?, 1, NOW())
            ");
            $stmt->execute([$identifier, $action]);
            return true;
        }
        
        // Check if within window
        $windowStart = strtotime($result['window_start']);
        if (time() - $windowStart > $window) {
            // New window
            $stmt = $db->prepare("
                UPDATE rate_limits 
                SET request_count = 1, window_start = NOW()
                WHERE identifier = ? AND action = ?
            ");
            $stmt->execute([$identifier, $action]);
            return true;
        }
        
        // Check limit
        if ($result['request_count'] >= $limit) {
            return false;
        }
        
        // Increment
        $stmt = $db->prepare("
            UPDATE rate_limits 
            SET request_count = request_count + 1
            WHERE identifier = ? AND action = ?
        ");
        $stmt->execute([$identifier, $action]);
        
        return true;
    } catch (Exception $e) {
        error_log('Rate limit check failed: ' . $e->getMessage());
        // Allow on error
        return true;
    }
}

/**
 * Get client identifier for rate limiting
 */
function getClientIdentifier() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Extract domain from URL
 */
function extractDomain($url) {
    $parsed = parse_url($url);
    return $parsed['host'] ?? $url;
}

/**
 * Check if HTTPS
 */
function isHttps($url) {
    $parsed = parse_url($url);
    return ($parsed['scheme'] ?? '') === 'https';
}

/**
 * Generate secure filename
 */
function generateSecureFilename($originalName) {
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    return generateRandomString(32) . ($extension ? '.' . $extension : '');
}

/**
 * Validate file upload
 */
function validateFileUpload($file, $allowedTypes, $maxSize) {
    if (!isset($file['error']) || is_array($file['error'])) {
        return ['valid' => false, 'error' => 'Invalid file upload'];
    }
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['valid' => false, 'error' => 'Upload error'];
    }
    
    if ($file['size'] > $maxSize) {
        return ['valid' => false, 'error' => 'File too large'];
    }
    
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    
    if (!in_array($mimeType, $allowedTypes)) {
        return ['valid' => false, 'error' => 'Invalid file type'];
    }
    
    return ['valid' => true];
}
