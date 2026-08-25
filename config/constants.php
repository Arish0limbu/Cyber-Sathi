<?php
/**
 * CYBERGUARD AI - Constants
 */

// User Roles
define('ROLE_USER', 'user');
define('ROLE_ADMIN', 'admin');

// User Status
define('STATUS_ACTIVE', 'active');
define('STATUS_INACTIVE', 'inactive');
define('STATUS_SUSPENDED', 'suspended');

// Scan Types
define('SCAN_URL', 'URL');
define('SCAN_DOMAIN', 'DOMAIN');
define('SCAN_IP', 'IP');
define('SCAN_EMAIL', 'EMAIL');
define('SCAN_FILE', 'FILE');
define('SCAN_QR', 'QR');
define('SCAN_MESSAGE', 'MESSAGE');
define('SCAN_SCREENSHOT', 'SCREENSHOT');

// Scan Status
define('SCAN_PENDING', 'pending');
define('SCAN_PROCESSING', 'processing');
define('SCAN_COMPLETED', 'completed');
define('SCAN_FAILED', 'failed');

// Risk Levels
define('RISK_LEVEL_SAFE', 'SAFE');
define('RISK_LEVEL_LOW', 'LOW');
define('RISK_LEVEL_MEDIUM', 'MEDIUM');
define('RISK_LEVEL_HIGH', 'HIGH');
define('RISK_LEVEL_CRITICAL', 'CRITICAL');

// Finding Severity
define('SEVERITY_LOW', 'LOW');
define('SEVERITY_MEDIUM', 'MEDIUM');
define('SEVERITY_HIGH', 'HIGH');
define('SEVERITY_CRITICAL', 'CRITICAL');

// Notification Types
define('NOTIFICATION_CRITICAL', 'critical');
define('NOTIFICATION_WARNING', 'warning');
define('NOTIFICATION_SUCCESS', 'success');
define('NOTIFICATION_INFO', 'info');

// API Key Status
define('API_KEY_ACTIVE', 'active');
define('API_KEY_REVOKED', 'revoked');
define('API_KEY_EXPIRED', 'expired');

// Contact Message Status
define('CONTACT_NEW', 'new');
define('CONTACT_READ', 'read');
define('CONTACT_REPLIED', 'replied');

// Log Actions
define('ACTION_LOGIN', 'LOGIN');
define('ACTION_LOGOUT', 'LOGOUT');
define('ACTION_PASSWORD_CHANGE', 'PASSWORD_CHANGE');
define('ACTION_SCAN_CREATED', 'SCAN_CREATED');
define('ACTION_REPORT_CREATED', 'REPORT_CREATED');
define('ACTION_API_REQUEST', 'API_REQUEST');
define('ACTION_ADMIN_ACTION', 'ADMIN_ACTION');
define('ACTION_USER_STATUS_CHANGED', 'USER_STATUS_CHANGED');
define('ACTION_SETTINGS_CHANGED', 'SETTINGS_CHANGED');

// File Paths
define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('LOG_DIR', __DIR__ . '/../logs/');
define('ASSETS_DIR', __DIR__ . '/../assets/');

// API Endpoints
define('API_BASE', APP_URL . '/api');
