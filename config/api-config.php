<?php
/**
 * CYBERGUARD AI - External API Configuration
 * 
 * IMPORTANT: Never commit real API keys to version control.
 * Set these values in your production environment or use environment variables.
 */

return [
    // Threat Intelligence API
    'threat_intelligence' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'custom'
    ],
    
    // AI Analysis API
    'ai' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'openai',
        'model' => 'gpt-4'
    ],
    
    // URL Reputation API
    'url_reputation' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'virustotal'
    ],
    
    // IP Reputation API
    'ip_reputation' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'abuseipdb'
    ],
    
    // Domain Intelligence API
    'domain_intelligence' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'whoisxmlapi'
    ],
    
    // Email Reputation API
    'email_reputation' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'custom'
    ],
    
    // Geolocation API
    'geolocation' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'ipapi'
    ],
    
    // DNS Intelligence API
    'dns_intelligence' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'custom'
    ],
    
    // Malware Analysis API
    'malware_analysis' => [
        'enabled' => false,
        'api_key' => '',
        'endpoint' => '',
        'provider' => 'virustotal'
    ]
];

// Helper function to get API config
function getApiConfig($service) {
    $config = require __DIR__ . '/api-config.php';
    return $config[$service] ?? null;
}

// Helper function to check if API is enabled
function isApiEnabled($service) {
    $config = getApiConfig($service);
    return $config && $config['enabled'] === true;
}
