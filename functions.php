<?php
declare(strict_types=1);
// Require Parsedown
require_once 'Parsedown.php';

/**
 * Simple logging function
 * @param string $message Log message
 * @param string $level Log level (INFO, WARNING, ERROR)
 * @param string $logFile Path to log file
 */
function logMessage(string $message, string $level = 'INFO', string $logFile = ''): void
{
    if (empty($logFile)) {
        return;
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $logEntry = "[$timestamp] [$level] [$ip] $message\n";
    
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

/**
 * Get client IP address (handles proxies)
 * @return string IP address
 */
function getClientIp(): string
{
    $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Check rate limit for IP address
 * @param string $ip IP address
 * @param string $rateLimitFile Path to rate limit file
 * @param int $maxAttempts Maximum attempts allowed
 * @param int $blockDuration Block duration in seconds
 * @return bool True if allowed, false if rate limited
 */
function checkRateLimit(string $ip, string $rateLimitFile, int $maxAttempts, int $blockDuration): bool
{
    $rateLimits = [];
    
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $rateLimits = json_decode($data, true) ?? [];
    }
    
    // Clean up old entries
    $now = time();
    foreach ($rateLimits as $key => $data) {
        if ($now - $data['timestamp'] > $blockDuration) {
            unset($rateLimits[$key]);
        }
    }
    
    // Check current IP
    if (!isset($rateLimits[$ip])) {
        $rateLimits[$ip] = ['attempts' => 0, 'timestamp' => $now];
    }
    
    $ipData = $rateLimits[$ip];
    
    // Check if blocked
    if ($ipData['attempts'] >= $maxAttempts) {
        $timeSinceFirst = $now - $ipData['timestamp'];
        if ($timeSinceFirst < $blockDuration) {
            return false;
        } else {
            // Reset after block duration
            $rateLimits[$ip] = ['attempts' => 0, 'timestamp' => $now];
        }
    }
    
    // Save and return
    file_put_contents($rateLimitFile, json_encode($rateLimits), LOCK_EX);
    return true;
}

/**
 * Record failed login attempt
 * @param string $ip IP address
 * @param string $rateLimitFile Path to rate limit file
 */
function recordFailedAttempt(string $ip, string $rateLimitFile): void
{
    $rateLimits = [];
    
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $rateLimits = json_decode($data, true) ?? [];
    }
    
    if (!isset($rateLimits[$ip])) {
        $rateLimits[$ip] = ['attempts' => 0, 'timestamp' => time()];
    }
    
    $rateLimits[$ip]['attempts']++;
    
    file_put_contents($rateLimitFile, json_encode($rateLimits), LOCK_EX);
}

/**
 * Clear session cookie properly
 */
function clearSessionCookie(): void
{
    if (isset($_COOKIE[session_name()])) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
}

/**
 * Handle image upload with enhanced security validation
 * @param array $file File from $_FILES
 * @param string $uploadsDir Directory for uploads
 * @param array $allowedTypes Allowed image types
 * @param int $maxSize Maximum file size
 * @return array Result with 'success' boolean and 'message' or 'filename'
 */
function handleImageUpload(array $file, string $uploadsDir, array $allowedTypes, int $maxSize): array
{
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'Upload error occurred'];
    }
    
    // Validate file size
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large (max ' . round($maxSize/1024/1024, 1) . 'MB)'];
    }
    
    // Use getimagesize for validation (checks if it's really an image)
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['success' => false, 'message' => 'File is not a valid image'];
    }
    
    // Check image type against whitelist
    $imageType = $imageInfo[2];
    if (!isset($allowedTypes[$imageType])) {
        return ['success' => false, 'message' => 'Image type not allowed'];
    }
    
    // Double-check MIME type with finfo
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($mimeType, $allowedMimes)) {
        return ['success' => false, 'message' => 'Invalid MIME type'];
    }
    
    // Check image dimensions (max 8000x8000)
    if ($imageInfo[0] > 8000 || $imageInfo[1] > 8000) {
        return ['success' => false, 'message' => 'Image dimensions too large'];
    }
    
    // Generate safe filename (timestamp + random + extension)
    $extension = $allowedTypes[$imageType];
    $filename = date('Y-m-d_His') . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
    $targetPath = $uploadsDir . '/' . $filename;
    
    // Create uploads directory if it doesn't exist
    if (!is_dir($uploadsDir)) {
        mkdir($uploadsDir, 0755, true);
    }
    
    // Move uploaded file
    if (!move_uploaded_file($file['tmp_name'], $targetPath)) {
        return ['success' => false, 'message' => 'Failed to save file'];
    }
    
    chmod($targetPath, 0644);
    
    return ['success' => true, 'filename' => $filename];
}

// Parse markdown
    // Require Parsedown (add at top of file after declare)
function parseMarkdown(string $text): string
{
    // Process hashtags BEFORE Parsedown
    $text = preg_replace_callback('/(^|\s)#([a-zA-Z0-9_\-]+)/', function($m) {
        return $m[1] . '<a href="?tag=' . urlencode($m[2]) . '" class="tag">#' . $m[2] . '</a>';
    }, $text);
    
    // Process wiki links
    $text = preg_replace_callback('/\[\[([^\]]+)\]\]/', function($m) {
        $page = trim($m[1]);
        return '<a href="?page=' . urlencode($page) . '" class="int">' . htmlspecialchars($page, ENT_QUOTES, 'UTF-8') . '</a>';
    }, $text);
    
    // Process image modifiers BEFORE Parsedown (convert to data attribute)
    $text = preg_replace_callback('/!\[([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/', function($m) {
        $alt = $m[1];
        $url = $m[2];
        $modifiers = $m[3];
        // Convert to format Parsedown will pass through, then we'll post-process
        return '![' . $alt . '](' . $url . ' "IMGMOD:' . $modifiers . '")';
    }, $text);
    
    // Use Parsedown
    $parsedown = new Parsedown();
    $parsedown->setSafeMode(false);
    $html = $parsedown->text($text);
    
    // Post-process: Apply image modifiers from title attribute
    $html = preg_replace_callback('/<img([^>]+)title="IMGMOD:([^"]+)"([^>]*)>/', function($m) {
        $before = $m[1];
        $modifiers = $m[2];
        $after = $m[3];
        
        // Extract classes from modifiers
        $classes = [];
        preg_match_all('/\.(\w+)/', $modifiers, $matches);
        foreach ($matches[1] as $class) {
            $classes[] = 'img-' . $class;
        }
        
        $classAttr = !empty($classes) ? ' class="' . implode(' ', $classes) . '"' : '';
        $style = ' style="max-width:100%; max-height:400px;"';
        
        // Rebuild img tag without the IMGMOD title
        return '<img' . $before . $classAttr . $style . $after . '>';
    }, $html);
    
    // Ensure regular images (without modifiers) have styling
    $html = preg_replace_callback('/<img(?![^>]*style=)([^>]+)>/', function($m) {
        return '<img' . $m[1] . ' style="max-width:100%; max-height:400px;">';
    }, $html);
    
    return $html;
}




/**
 * Get list of all existing page names for auto-linking
 * @param string $pagesDir Pages directory
 * @return array List of page names sorted by length (longest first)
 */
function getAllPageNames(string $pagesDir): array
{
    static $cachedPages = null;
    
    if ($cachedPages !== null) {
        return $cachedPages;
    }
    
    $pages = [];
    $files = glob("$pagesDir/*.md");
    
    if ($files !== false) {
        foreach ($files as $file) {
            $pages[] = basename($file, '.md');
        }
    }
    
    usort($pages, function($a, $b) {
        return strlen($b) - strlen($a);
    });
    
    $cachedPages = $pages;
    return $pages;
}

/**
 * Automatically link page names found in text
 * @param string $text The text to process
 * @param string $pagesDir Pages directory
 * @param string $currentPage Current page
 * @return string Text with automatic links added
 */
function autoLinkPageNames(string $text, string $pagesDir, string $currentPage): string
{
    $allPages = getAllPageNames($pagesDir);
    
    $allPages = array_filter($allPages, function($page) use ($currentPage) {
        return strcasecmp($page, $currentPage) !== 0;
    });
    
    $allPages = array_filter($allPages, function($page) {
        return strlen($page) >= 3;
    });
    
    foreach ($allPages as $page) {
        $escapedPage = preg_quote($page, '/');
        // UPDATED: Don't match if preceded by # (hashtag)
        $pattern = '/(?<!\[\[)(?<!\[)(?<!\#)\b(' . $escapedPage . ')\b(?!\]\])(?!\])/i';
        
        $replaced = false;
        $text = preg_replace_callback($pattern, function($matches) use (&$replaced) {
            if ($replaced) {
                return $matches[0];
            }
            $replaced = true;
            return '[[' . $matches[1] . ']]';
        }, $text);
    }
    
    return $text;
}


/**
 * Enhanced markdown parser with auto-linking
 * @param string $text Raw markdown content
 * @param string $pagesDir Pages directory
 * @param string $currentPage Current page name
 * @param bool $enableAutoLink Whether to enable automatic linking
 * @return string HTML output
 */
function parseMarkdownWithAutoLink(string $text, string $pagesDir, string $currentPage, bool $enableAutoLink = true): string
{
    if ($enableAutoLink) {
        $text = autoLinkPageNames($text, $pagesDir, $currentPage);
    }
    
    return parseMarkdown($text);
}

/**
 * Find all pages that link to the current page
 * @param string $currentPage The page to find backlinks for
 * @param string $pagesDir Directory containing markdown files
 * @return array List of page names that link to current page
 */
function getBacklinks(string $currentPage, string $pagesDir): array
{
    $backlinks = [];
    $files = glob("$pagesDir/*.md");
    
    if ($files === false) {
        return $backlinks;
    }
    
    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        
        if (strcasecmp($pageName, $currentPage) === 0) {
            continue;
        }
        
        $content = file_get_contents($file);
        if ($content === false) {
            continue;
        }
        
        if (preg_match('/\[\[' . preg_quote($currentPage, '/') . '\]\]/i', $content)) {
            $backlinks[] = $pageName;
        }
    }
    
    return $backlinks;
}

/**
 * Find related pages based on shared tags
 * @param string $currentPage Current page name
 * @param string $content Current page content
 * @param string $pagesDir Pages directory
 * @param int $limit Maximum number of suggestions
 * @return array Related pages with shared tag counts
 */
function getRelatedPagesByTags(string $currentPage, string $content, string $pagesDir, int $limit = 5): array
{
    preg_match_all('/#([a-zA-Z0-9_\-]+)/', $content, $currentTags);
    $currentTags = $currentTags[1];
    
    if (empty($currentTags)) {
        return [];
    }
    
    $related = [];
    $files = glob("$pagesDir/*.md");
    
    if ($files === false) {
        return [];
    }
    
    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        
        if (strcasecmp($pageName, $currentPage) === 0) {
            continue;
        }
        
        $otherContent = file_get_contents($file);
        if ($otherContent === false) {
            continue;
        }
        
        preg_match_all('/#([a-zA-Z0-9_\-]+)/', $otherContent, $otherTags);
        $otherTags = $otherTags[1];
        
        $sharedTags = array_intersect($currentTags, $otherTags);
        $sharedCount = count($sharedTags);
        
        if ($sharedCount > 0) {
            $related[$pageName] = [
                'count' => $sharedCount,
                'tags' => $sharedTags
            ];
        }
    }
    
    uasort($related, function($a, $b) {
        return $b['count'] - $a['count'];
    });
    
    return array_slice($related, 0, $limit, true);
}

/**
 * Generate a cryptographically secure nonce
 * @return string Base64 encoded nonce
 */
function generateNonce(): string
{
    return base64_encode(random_bytes(16));
}

/**
 * Render navigation bar
 * @param string $nonce CSP nonce for inline scripts
 */
function renderNav(string $nonce = ''): void
{
    ?>
    <nav>
        <a href="index.php">Home</a>
        <a href="?page=AllPages">All Pages</a>
        <a href="?page=AllTags">All Tags</a>
        <?php if ($_SESSION['loggedin'] ?? false): ?>
            <a href="?logout=1">Logout (<?= htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8') ?>)</a>
        <?php endif; ?>
        <form method="get" style="display:inline;">
            <input type="text" name="q" placeholder="Search" value="<?= htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') ?>" maxlength="100">
            <button type="submit" name="search">🔍</button>
        </form>
    </nav>
    <?php
}

/**
 * Render complete HTML page
 * @param string $title Page title
 * @param callable $contentCallback Function that outputs page content
 * @param string $nonce CSP nonce for inline scripts
 */
function renderPage(string $title, callable $contentCallback, string $nonce = ''): void
{
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($title, ENT_QUOTES, 'UTF-8') ?> - Simple Wiki</title>
    <link rel="stylesheet" type="text/css" href="styles.css">
</head>
<body>
    <?php renderNav($nonce); ?>
    <?php $contentCallback(); ?>
    <script src="wiki.js" nonce="<?= $nonce ?>"></script>
</body>
</html>
    <?php
}

