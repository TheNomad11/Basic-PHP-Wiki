<?php
declare(strict_types=1);

// Protection script - blocks direct access to sensitive files
// Works on both Apache and Nginx

$requestUri = $_SERVER['REQUEST_URI'] ?? '';

// Block access to sensitive files
$blockedPatterns = [
    '/\.json$/i',           // JSON files
    '/\.(md|txt)$/i',       // Markdown and text files
    '/\.meta$/i',           // Metadata files
    '/\/(functions|protect|config)\.php$/i', // PHP includes
    '/rate_limits\.json$/i', // Rate limit data
    '/wiki\.log$/i'         // Log file
];

foreach ($blockedPatterns as $pattern) {
    if (preg_match($pattern, $requestUri)) {
        http_response_code(403);
        header('X-Robots-Tag: noindex');
        die('Access denied');
    }
}

// Only allow image files in uploads directory
if (preg_match('/\/uploads\//', $requestUri)) {
    if (!preg_match('/\.(jpg|jpeg|png|gif|webp)$/i', $requestUri)) {
        http_response_code(403);
        die('Access denied');
    }
}
