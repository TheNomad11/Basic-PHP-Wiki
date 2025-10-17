<?php
// Protection script - blocks direct access to sensitive files
// Works on both Apache and Nginx

$requestUri = $_SERVER['REQUEST_URI'] ?? '';

// Block access to .json files
if (preg_match('/\.json$/i', $requestUri)) {
    http_response_code(403);
    die('Access denied');
}

// Block access to .md and .txt files
if (preg_match('/\.(md|txt)$/i', $requestUri)) {
    http_response_code(403);
    die('Access denied');
}

// Block access to functions.php and protect.php
if (preg_match('/\/(functions|protect)\.php$/i', $requestUri)) {
    http_response_code(403);
    die('Access denied');
}

// Only allow image files in uploads directory
if (preg_match('/\/uploads\//', $requestUri)) {
    if (!preg_match('/\.(jpg|jpeg|png|gif|webp)$/i', $requestUri)) {
        http_response_code(403);
        die('Access denied');
    }
}
