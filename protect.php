<?php
declare(strict_types=1);

// Protection script - blocks direct access to sensitive files
// Works on both Apache and Nginx

// Protect against direct access to this file and other includes
$scriptName = basename($_SERVER['SCRIPT_FILENAME'] ?? '');
$protectedScripts = ['protect.php', 'functions.php', 'config.php'];

if (in_array($scriptName, $protectedScripts)) {
    http_response_code(403);
    header('X-Robots-Tag: noindex');
    die('Access denied');
}

$requestUri = $_SERVER['REQUEST_URI'] ?? '';

// Block access to sensitive files
$blockedPatterns = [
    '/\.json$/i',           // JSON files (old format, should be .json.php now)
    '/\.json\.php$/i',      // Protected JSON files
    '/\.(md|txt)$/i',       // Markdown and text files (includes .md.rev files)
    '/\.meta$/i',           // Metadata files
    '/\/(functions|protect|config)\.php$/i', // PHP includes
    '/rate_limits\./i',     // Rate limit data
    '/wiki\.log/i',         // Log file
    '/wikilog\.php$/i'      // Log file (PHP format)
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

// Block direct access to pages directory
if (preg_match('/\/pages\//', $requestUri)) {
    http_response_code(403);
    header('X-Robots-Tag: noindex');
    die('Access denied');
}

// Block direct access to cache directory
if (preg_match('/\/cache\//', $requestUri)) {
    http_response_code(403);
    die('Access denied');
}

// Block direct access to sessions directory
if (preg_match('/\/sessions\//', $requestUri)) {
    http_response_code(403);
    die('Access denied');
}
