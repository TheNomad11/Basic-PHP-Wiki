<?php
/**
 * Configuration file for Simple Wiki
 */

return [
    'wiki_title' => 'Simple Wiki',
    
    'pages_dir' => __DIR__ . '/pages',
    
    'uploads_dir' => __DIR__ . '/uploads',
    
    'sessions_dir' => __DIR__ . '/sessions',
    
    'users_file' => __DIR__ . '/users.json',
    
    'rate_limit_file' => __DIR__ . '/rate_limits.json',
    
    'log_file' => __DIR__ . '/wiki.log',
    
    'default_page' => 'Home',
    
    'enable_auto_link' => true,
    
    // Security settings
    'session_lifetime' => 3600, // 1 hour
    
    'session_timeout' => 1800, // 30 minutes inactivity
    
    'max_login_attempts' => 5, // per IP
    
    'login_block_duration' => 300, // 5 minutes
    
    'max_upload_size' => 5242880, // 5MB
    
    'max_content_size' => 1048576, // 1MB
    
    // Allowed image types
    'allowed_image_types' => [
        IMAGETYPE_JPEG => 'jpg',
        IMAGETYPE_PNG => 'png',
        IMAGETYPE_GIF => 'gif',
        IMAGETYPE_WEBP => 'webp'
    ]
];
