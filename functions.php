<?php
declare(strict_types=1);

// Load configuration
$config = require __DIR__ . '/config.php';

// Define constants from config
define('PAGES_DIR', $config['pages_dir']);
define('UPLOADS_DIR', $config['uploads_dir']);
define('SESSIONS_DIR', $config['sessions_dir'] ?? __DIR__ . '/sessions');
define('USERS_FILE', $config['users_file'] ?? __DIR__ . '/users.json');
define('RATE_LIMIT_FILE', $config['rate_limit_file']);
define('LOG_FILE', $config['log_file']);
define('TRUST_PROXY', false);
define('MAX_UPLOAD_SIZE', $config['max_upload_size']);
define('SESSION_LIFETIME', $config['session_lifetime']);
define('SESSION_TIMEOUT', $config['session_timeout']);
define('RATE_MAX_ATTEMPTS', $config['max_login_attempts']);
define('RATE_BLOCK_SECONDS', $config['login_block_duration']);
define('MAX_IMAGE_WIDTH', 8000);
define('MAX_IMAGE_HEIGHT', 8000);
define('MAX_PAGE_NAME_LENGTH', 100);
define('MAX_SEARCH_LENGTH', 100);
define('MAX_TAG_LENGTH', 50);
define('CACHE_DIR', $config['cache_dir'] ?? __DIR__ . '/cache');
define('SEARCH_INDEX_FILE', CACHE_DIR . '/search_index.json');
define('PAGES_PER_PAGE', 50);

// Require Parsedown
require_once 'Parsedown.php';

// DO NOT start session here - let index.php handle it
// This file only contains utility functions

// -----------------------------
// Utility: Logging
// -----------------------------
/**
 * Log a message to the log file
 * 
 * @param string $message Message to log
 * @param string $level Log level (INFO, WARNING, ERROR)
 * @param string $logFile Path to log file
 * @return bool Success status
 */
function logMessage(string $message, string $level = 'INFO', string $logFile = LOG_FILE): bool
{
    if (empty($logFile)) {
        return false;
    }

    $timestamp = gmdate('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $logEntry = "[$timestamp] [$level] [$ip] $message\n";

    $dir = dirname($logFile);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true) && !is_dir($dir)) {
            return false;
        }
    }

    $fh = fopen($logFile, 'a');
    if ($fh === false) {
        return false;
    }

    $success = false;
    if (flock($fh, LOCK_EX)) {
        fwrite($fh, $logEntry);
        fflush($fh);
        flock($fh, LOCK_UN);
        $success = true;
    }
    fclose($fh);
    
    return $success;
}

// -----------------------------
// Utility: safe client IP
// -----------------------------
function getClientIp(): string
{
    if (TRUST_PROXY) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        if (!empty($_SERVER['HTTP_X_REAL_IP']) && filter_var($_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_X_REAL_IP'];
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// -----------------------------
// Atomic read/write helpers for JSON files (with locking)
// -----------------------------
function readJsonFileLocked(string $file): array
{
    if (!file_exists($file)) {
        return [];
    }

    $fh = fopen($file, 'r');
    if ($fh === false) {
        logMessage("Failed to open file for reading: $file", 'ERROR');
        return [];
    }

    $data = [];
    if (flock($fh, LOCK_SH)) {
        $contents = stream_get_contents($fh);
        if ($contents !== false) {
            $decoded = json_decode($contents, true);
            $data = is_array($decoded) ? $decoded : [];
        }
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    return $data;
}

function writeJsonFileLocked(string $file, array $data): bool
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true) && !is_dir($dir)) {
            logMessage("Failed to create directory: $dir", 'ERROR');
            return false;
        }
    }

    $tmp = $file . '.tmp.' . bin2hex(random_bytes(8));
    $fh = fopen($tmp, 'w');
    if ($fh === false) {
        logMessage("Failed to create temp file: $tmp", 'ERROR');
        return false;
    }

    $success = false;
    if (flock($fh, LOCK_EX)) {
        $written = fwrite($fh, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($fh);
        flock($fh, LOCK_UN);
        
        if ($written !== false) {
            $success = rename($tmp, $file);
            if (!$success) {
                logMessage("Failed to rename temp file to: $file", 'ERROR');
            }
        }
    }
    fclose($fh);

    if (!$success && file_exists($tmp)) {
        unlink($tmp);
    }

    return $success;
}

// -----------------------------
// Rate limit functions
// -----------------------------
function checkRateLimit(string $identifier, string $rateLimitFile = RATE_LIMIT_FILE, int $maxAttempts = RATE_MAX_ATTEMPTS, int $blockDuration = RATE_BLOCK_SECONDS): bool
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    $now = time();

    // Cleanup expired entries
    $cleaned = false;
    foreach ($rateLimits as $k => $v) {
        if (!isset($v['first']) || ($now - (int)$v['first']) > $blockDuration) {
            unset($rateLimits[$k]);
            $cleaned = true;
        }
    }
    
    if ($cleaned) {
        writeJsonFileLocked($rateLimitFile, $rateLimits);
    }

    if (!isset($rateLimits[$identifier])) {
        return true;
    }

    $entry = $rateLimits[$identifier];
    
    if (($entry['count'] ?? 0) >= $maxAttempts) {
        $elapsed = $now - (int)$entry['first'];
        if ($elapsed < $blockDuration) {
            return false;
        }
    }

    return true;
}

function recordFailedAttempt(string $identifier, string $rateLimitFile = RATE_LIMIT_FILE): void
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    $now = time();

    if (!isset($rateLimits[$identifier]) || ($now - (int)$rateLimits[$identifier]['first']) > RATE_BLOCK_SECONDS) {
        $rateLimits[$identifier] = ['count' => 1, 'first' => $now];
    } else {
        $rateLimits[$identifier]['count'] = ($rateLimits[$identifier]['count'] ?? 0) + 1;
    }

    writeJsonFileLocked($rateLimitFile, $rateLimits);
}

function resetRateLimit(string $identifier, string $rateLimitFile = RATE_LIMIT_FILE): void
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    unset($rateLimits[$identifier]);
    writeJsonFileLocked($rateLimitFile, $rateLimits);
}

// -----------------------------
// Session / cookie helpers
// -----------------------------
function clearSessionCookie(): void
{
    if (isset($_COOKIE[session_name()])) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'] ?? '/',
            $params['domain'] ?? '',
            $params['secure'] ?? false,
            $params['httponly'] ?? true
        );
    }
}

// -----------------------------
// CSRF helpers
// -----------------------------
function generateCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(?string $token): bool
{
    $stored = $_SESSION['csrf_token'] ?? '';
    if (empty($stored) || empty($token)) {
        return false;
    }
    return hash_equals($stored, $token);
}

// -----------------------------
// Image upload handler
// -----------------------------
function ensureUploadsDir(string $uploadsDir = UPLOADS_DIR): void
{
    if (!is_dir($uploadsDir)) {
        if (!mkdir($uploadsDir, 0755, true) && !is_dir($uploadsDir)) {
            logMessage("Failed to create uploads directory: $uploadsDir", 'ERROR');
            return;
        }
    }
    
    $htaccess = $uploadsDir . '/.htaccess';
    if (!file_exists($htaccess)) {
        $content = "Options -Indexes\n<FilesMatch \"\\.(php|phtml|php3|phps)$\">\n    Deny from all\n</FilesMatch>\n";
        if (file_put_contents($htaccess, $content, LOCK_EX) === false) {
            logMessage("Failed to create .htaccess in uploads directory", 'WARNING');
        }
    }
}

function handleImageUpload(array $file, string $uploadsDir = UPLOADS_DIR, int $maxSize = MAX_UPLOAD_SIZE): array
{
    ensureUploadsDir($uploadsDir);

    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'Upload error occurred'];
    }
    
    if (!is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'message' => 'Possible file upload attack'];
    }
    
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large (max ' . round($maxSize/1024/1024, 1) . 'MB)'];
    }

    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['success' => false, 'message' => 'File is not a valid image'];
    }
    
    [$width, $height, $imageType] = [$imageInfo[0], $imageInfo[1], $imageInfo[2]];

    if ($width > MAX_IMAGE_WIDTH || $height > MAX_IMAGE_HEIGHT) {
        return ['success' => false, 'message' => 'Image dimensions too large'];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp'
    ];
    
    if (!isset($allowedMimes[$mimeType])) {
        return ['success' => false, 'message' => 'Invalid MIME type'];
    }

    $extension = $allowedMimes[$mimeType];
    $filename = date('Y-m-d_His') . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
    $targetPath = $uploadsDir . '/' . $filename;

    $srcImg = null;
    switch ($mimeType) {
        case 'image/jpeg':
            $srcImg = @imagecreatefromjpeg($file['tmp_name']);
            break;
        case 'image/png':
            $srcImg = @imagecreatefrompng($file['tmp_name']);
            break;
        case 'image/gif':
            $srcImg = @imagecreatefromgif($file['tmp_name']);
            break;
        case 'image/webp':
            if (function_exists('imagecreatefromwebp')) {
                $srcImg = @imagecreatefromwebp($file['tmp_name']);
            }
            break;
    }
    
    if ($srcImg === false || $srcImg === null) {
        return ['success' => false, 'message' => 'Failed to process image'];
    }

    if ($width > MAX_IMAGE_WIDTH || $height > MAX_IMAGE_HEIGHT) {
        $ratio = min(MAX_IMAGE_WIDTH / $width, MAX_IMAGE_HEIGHT / $height);
        $newW = (int)($width * $ratio);
        $newH = (int)($height * $ratio);
        $tmpImg = imagecreatetruecolor($newW, $newH);
        imagecopyresampled($tmpImg, $srcImg, 0, 0, 0, 0, $newW, $newH, $width, $height);
        imagedestroy($srcImg);
        $srcImg = $tmpImg;
    }

    $saved = false;
    switch ($extension) {
        case 'jpg':
            $saved = imagejpeg($srcImg, $targetPath, 85);
            break;
        case 'png':
            $saved = imagepng($srcImg, $targetPath, 6);
            break;
        case 'gif':
            $saved = imagegif($srcImg, $targetPath);
            break;
        case 'webp':
            if (function_exists('imagewebp')) {
                $saved = imagewebp($srcImg, $targetPath, 80);
            }
            break;
    }
    imagedestroy($srcImg);

    if (!$saved) {
        return ['success' => false, 'message' => 'Failed to save processed image'];
    }

    chmod($targetPath, 0644);
    return ['success' => true, 'filename' => $filename];
}

// -----------------------------
// Markdown parsing & sanitization
// -----------------------------
function sanitizeTextForAttr(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function preprocessWikiLinks(string $text): string {
    return preg_replace_callback('/\[\[([^\]]+)\]\]/', function($m) {
        $page = trim($m[1]);
        $safePage = rawurlencode($page);
        return '[' . htmlspecialchars($page, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '](?page=' . $safePage . ')';
    }, $text);
}

function parseMarkdown(string $text): string
{
    // Pre-process hashtags
    $text = preg_replace_callback('/(^|\s)#([a-zA-Z0-9_\-]+)/', function($m) {
        $prefix = $m[1];
        $tag = $m[2];
        return $prefix . '[#' . $tag . '](' . '?tag=' . rawurlencode($tag) . ')';
    }, $text);

    // Pre-process wiki links
    $text = preprocessWikiLinks($text);
    
    // Process image modifiers
    $text = preg_replace_callback('/!\[([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/', function($m) {
        $alt = $m[1];
        $url = $m[2];
        $modifiers = $m[3];
        $safeModifiers = str_replace('"', '&quot;', $modifiers);
        return '![' . $alt . '](' . $url . ' "IMGMOD:' . $safeModifiers . '")';
    }, $text);

    // Use Parsedown safe mode
    $parsedown = new Parsedown();
    $parsedown->setSafeMode(true);
    $html = $parsedown->text($text);

    // Post-process tag links
    $html = preg_replace_callback('/<a href="([^"]+)">#([^<]+)<\/a>/', function($m) {
        $href = sanitizeTextForAttr($m[1]);
        $tag  = htmlspecialchars($m[2], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return '<a href="' . $href . '" class="tag">#' . $tag . '</a>';
    }, $html);

    // Post-process image modifiers
    $html = preg_replace_callback('/<img([^>]*)title="IMGMOD:([^"]+)"([^>]*)>/i', function($m) {
        $before = $m[1];
        $modifiers = $m[2];
        $after = $m[3];

        $classes = [];
        if (preg_match_all('/\.(\w[\w-]*)/', $modifiers, $cmatches)) {
            foreach ($cmatches[1] as $c) {
                $classes[] = 'img-' . htmlspecialchars($c, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            }
        }
        $classAttr = $classes ? ' class="' . implode(' ', $classes) . '"' : '';
        $style = ' style="max-width:100%; max-height:400px;"';
        return '<img' . $before . $classAttr . $style . $after . '>';
    }, $html);

    // Ensure all images have max dimensions
    $html = preg_replace_callback('/<img((?:(?!style=)[^>])*)>/i', function($m) {
        $attrs = $m[1];
        if (stripos($attrs, 'style=') !== false) {
            return '<img' . $attrs . '>';
        }
        return '<img' . $attrs . ' style="max-width:100%; max-height:400px;">';
    }, $html);

    return $html;
}

// -----------------------------
// Page listing / auto-linking helpers
// -----------------------------
function getAllPageNames(string $pagesDir = PAGES_DIR): array
{
    $pages = [];
    if (!is_dir($pagesDir)) {
        if (!mkdir($pagesDir, 0755, true) && !is_dir($pagesDir)) {
            return [];
        }
    }
    
    $files = glob($pagesDir . '/*.md');
    if ($files !== false) {
        foreach ($files as $f) {
            $pages[] = basename($f, '.md');
        }
    }
    
    usort($pages, function($a, $b) { 
        return strlen($b) - strlen($a); 
    });
    
    return $pages;
}

function safePageName(string $name): string
{
    $name = preg_replace('/[^\p{L}\p{N} _\-]/u', '', $name);
    $name = preg_replace('/\s+/', ' ', trim($name));
    if ($name === '') {
        return 'Home';
    }
    return $name;
}

function autoLinkPageNames(string $text, string $pagesDir = PAGES_DIR, string $currentPage = ''): string
{
    $allPages = getAllPageNames($pagesDir);
    $filtered = array_filter($allPages, function($p) use ($currentPage) {
        return strcasecmp($p, $currentPage) !== 0 && strlen($p) >= 3;
    });

    foreach ($filtered as $page) {
        $escapedPage = preg_quote($page, '/');
        $pattern = '/(?<!\[\[)(?<!\[)(?<!\#)\b(' . $escapedPage . ')\b(?!\]\])/i';
        $replaced = false;
        $text = preg_replace_callback($pattern, function($matches) use (&$replaced) {
            if ($replaced) return $matches[0];
            $replaced = true;
            return '[[' . $matches[1] . ']]';
        }, $text, 1);
    }
    return $text;
}

function parseMarkdownWithAutoLink(string $text, string $pagesDir = PAGES_DIR, string $currentPage = '', bool $enableAutoLink = true): string
{
    if ($enableAutoLink) {
        $text = autoLinkPageNames($text, $pagesDir, $currentPage);
    }
    return parseMarkdown($text);
}

// -----------------------------
// Caching functions
// -----------------------------
/**
 * Get cached parsed HTML for a page
 * 
 * @param string $pageName Page name
 * @param string $content Raw markdown content
 * @return string|null Cached HTML or null if not cached or outdated
 */
function getCachedHtml(string $pageName, string $content): ?string
{
    $cacheDir = CACHE_DIR;
    if (!is_dir($cacheDir)) {
        if (!mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
            return null;
        }
    }
    
    $cacheFile = $cacheDir . '/' . md5($pageName) . '.html';
    $hashFile = $cacheFile . '.hash';
    
    if (!file_exists($cacheFile) || !file_exists($hashFile)) {
        return null;
    }
    
    // Check if content has changed
    $currentHash = md5($content);
    $cachedHash = file_get_contents($hashFile);
    
    if ($currentHash !== $cachedHash) {
        return null;
    }
    
    return file_get_contents($cacheFile);
}

/**
 * Save parsed HTML to cache
 * 
 * @param string $pageName Page name
 * @param string $content Raw markdown content
 * @param string $html Parsed HTML
 * @return bool Success status
 */
function setCachedHtml(string $pageName, string $content, string $html): bool
{
    $cacheDir = CACHE_DIR;
    if (!is_dir($cacheDir)) {
        if (!mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
            return false;
        }
    }
    
    $cacheFile = $cacheDir . '/' . md5($pageName) . '.html';
    $hashFile = $cacheFile . '.hash';
    
    $contentHash = md5($content);
    
    $result1 = file_put_contents($cacheFile, $html, LOCK_EX);
    $result2 = file_put_contents($hashFile, $contentHash, LOCK_EX);
    
    if ($result1 !== false && $result2 !== false) {
        chmod($cacheFile, 0644);
        chmod($hashFile, 0644);
        return true;
    }
    
    return false;
}

/**
 * Clear cache for a specific page
 * 
 * @param string $pageName Page name
 */
function clearPageCache(string $pageName): void
{
    $cacheDir = CACHE_DIR;
    $cacheFile = $cacheDir . '/' . md5($pageName) . '.html';
    $hashFile = $cacheFile . '.hash';
    
    if (file_exists($cacheFile)) {
        unlink($cacheFile);
    }
    if (file_exists($hashFile)) {
        unlink($hashFile);
    }
}

// -----------------------------
// Search index functions
// -----------------------------
/**
 * Build search index for all pages
 * 
 * @param string $pagesDir Pages directory
 * @return bool Success status
 */
function buildSearchIndex(string $pagesDir = PAGES_DIR): bool
{
    $index = [];
    $files = glob($pagesDir . '/*.md');
    
    if ($files === false) {
        return false;
    }
    
    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        $content = file_get_contents($file);
        
        if ($content === false) {
            continue;
        }
        
        // Remove markdown syntax for better search
        $searchableContent = strip_tags(parseMarkdown($content));
        $searchableContent = strtolower($searchableContent);
        
        $index[$pageName] = [
            'name' => $pageName,
            'content' => $searchableContent,
            'length' => strlen($content),
            'mtime' => filemtime($file)
        ];
    }
    
    return writeJsonFileLocked(SEARCH_INDEX_FILE, $index);
}

/**
 * Get search index, rebuilding if necessary
 * 
 * @param string $pagesDir Pages directory
 * @return array Search index
 */
function getSearchIndex(string $pagesDir = PAGES_DIR): array
{
    $indexFile = SEARCH_INDEX_FILE;
    
    // Check if index exists and is recent (less than 1 hour old)
    if (file_exists($indexFile)) {
        $indexAge = time() - filemtime($indexFile);
        if ($indexAge < 3600) {
            return readJsonFileLocked($indexFile);
        }
    }
    
    // Rebuild index
    buildSearchIndex($pagesDir);
    return readJsonFileLocked($indexFile);
}

/**
 * Search using the index
 * 
 * @param string $query Search query
 * @param string $pagesDir Pages directory
 * @return array Array of [pageName => snippet]
 */
function searchWithIndex(string $query, string $pagesDir = PAGES_DIR): array
{
    $index = getSearchIndex($pagesDir);
    $results = [];
    $queryLower = strtolower($query);
    
    foreach ($index as $pageName => $data) {
        // Search in page name
        if (stripos($data['name'], $query) !== false) {
            $results[$pageName] = '<mark>' . htmlspecialchars($data['name'], ENT_QUOTES, 'UTF-8') . '</mark> (name match)';
            continue;
        }
        
        // Search in content
        if (stripos($data['content'], $queryLower) !== false) {
            $pos = stripos($data['content'], $queryLower);
            $start = max(0, $pos - 60);
            $length = min(120, strlen($data['content']) - $start);
            $snippet = substr($data['content'], $start, $length);
            
            $snippet = preg_replace(
                '/(' . preg_quote($query, '/') . ')/i',
                '<mark>$1</mark>',
                htmlspecialchars($snippet, ENT_QUOTES, 'UTF-8')
            );
            
            $results[$pageName] = $snippet;
        }
    }
    
    return $results;
}

// -----------------------------
// Backlinks & related pages
// -----------------------------
function getBacklinks(string $currentPage, string $pagesDir = PAGES_DIR): array
{
    $backlinks = [];
    if (!is_dir($pagesDir)) {
        return $backlinks;
    }
    
    $files = glob($pagesDir . '/*.md');
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

function getRelatedPagesByTags(string $currentPage, string $content, string $pagesDir = PAGES_DIR, int $limit = 5): array
{
    // Split into lines for better processing
    $lines = explode("\n", $content);
    $cleanedLines = [];
    
    foreach ($lines as $line) {
        // Skip lines that start with # (markdown headings)
        if (preg_match('/^\s*#{1,6}\s/', $line)) {
            continue;
        }
        
        // Skip code blocks
        if (preg_match('/^\s*```/', $line)) {
            continue;
        }
        
        // Skip indented code blocks
        if (preg_match('/^\s{4,}/', $line)) {
            continue;
        }
        
        $cleanedLines[] = $line;
    }
    
    $contentWithoutCode = implode("\n", $cleanedLines);
    
    // Remove inline code
    $contentWithoutCode = preg_replace('/`[^`]+`/', '', $contentWithoutCode);
    
    // Remove markdown links [text](url)
    $contentWithoutCode = preg_replace('/\[([^\]]+)\]\([^\)]+\)/', '$1', $contentWithoutCode);

    // Extract tags
    preg_match_all('/(?:^|\s)#([a-zA-Z0-9_\-]+)(?:\s|$)/m', $contentWithoutCode, $m);
    $currentTags = $m[1] ?? [];
    if (empty($currentTags)) {
        return [];
    }

    $related = [];
    $files = glob($pagesDir . '/*.md');
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
        
        // Same cleanup for other pages
        $otherLines = explode("\n", $otherContent);
        $otherCleanedLines = [];
        
        foreach ($otherLines as $line) {
            if (preg_match('/^\s*#{1,6}\s/', $line)) {
                continue;
            }
            if (preg_match('/^\s*```/', $line)) {
                continue;
            }
            if (preg_match('/^\s{4,}/', $line)) {
                continue;
            }
            $otherCleanedLines[] = $line;
        }
        
        $otherContent = implode("\n", $otherCleanedLines);
        $otherContent = preg_replace('/`[^`]+`/', '', $otherContent);
        $otherContent = preg_replace('/\[([^\]]+)\]\([^\)]+\)/', '$1', $otherContent);
        
        preg_match_all('/(?:^|\s)#([a-zA-Z0-9_\-]+)(?:\s|$)/m', $otherContent, $om);
        $otherTags = $om[1] ?? [];
        $shared = array_intersect($currentTags, $otherTags);
        
        if (count($shared) > 0) {
            $related[$pageName] = ['count' => count($shared), 'tags' => $shared];
        }
    }
    
    uasort($related, function($a, $b) { 
        return $b['count'] - $a['count']; 
    });
    
    return array_slice($related, 0, $limit, true);
}

// -----------------------------
// Security headers
// -----------------------------
function sendSecurityHeaders(string $nonce): void
{
    // Note: Removed 'unsafe-eval' as it's not needed for localStorage
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer-when-downgrade');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('X-XSS-Protection: 1; mode=block');
    
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    }
}

// -----------------------------
// Nonce & rendering helpers
// -----------------------------
function generateNonce(): string
{
    return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
}

function renderNav(string $nonce = ''): void
{
    $searchVal = htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $loggedIn = $_SESSION['loggedin'] ?? false;
    $user = htmlspecialchars($_SESSION['user'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $csrf = generateCsrfToken();
    ?>
    <nav>
        <a href="index.php">Home</a>
        <a href="?page=AllPages">All Pages</a>
        <a href="?page=AllTags">All Tags</a>
        <a href="?page=RecentChanges">Recent Changes</a>
        <?php if ($loggedIn): ?>
            <form method="post" style="display:inline;">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                <button type="submit" name="logout">Logout (<?= $user ?>)</button>
            </form>
        <?php endif; ?>
        <form method="get" style="display:inline;">
            <input type="text" name="q" placeholder="Search" value="<?= $searchVal ?>" maxlength="<?= MAX_SEARCH_LENGTH ?>">
            <button type="submit" name="search">🔍</button>
        </form>
    </nav>
    <?php
}

function renderPage(string $title, callable $contentCallback, string $nonce = ''): void
{
    sendSecurityHeaders($nonce);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?> - Simple Wiki</title>
    <link rel="stylesheet" type="text/css" href="styles.css">
</head>
<body>
    <?php renderNav($nonce); ?>
    <?php $contentCallback(); ?>
    <script src="wiki.js" nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"></script>
</body>
</html>
    <?php
}

/**
 * Validate password hashes in users file
 * Returns array of usernames with invalid hashes
 */
function validateUserPasswords(string $usersFile = USERS_FILE): array
{
    if (!file_exists($usersFile)) {
        return [];
    }
    
    $users = json_decode(file_get_contents($usersFile), true);
    if (!is_array($users)) {
        return [];
    }
    
    $invalid = [];
    foreach ($users as $username => $hash) {
        $info = password_get_info($hash);
        if ($info['algo'] === null) {
            $invalid[] = $username;
        }
    }
    
    return $invalid;
}

/**
 * Get recent changes with metadata
 * 
 * @param string $pagesDir Pages directory
 * @param int $limit Maximum number of changes to return
 * @return array Array of changes with page name, timestamp, and user
 */
function getRecentChanges(string $pagesDir = PAGES_DIR, int $limit = 50): array
{
    if (!is_dir($pagesDir)) {
        return [];
    }
    
    $changes = [];
    $files = glob($pagesDir . '/*.md');
    
    if ($files === false) {
        return [];
    }
    
    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        $mtime = filemtime($file);
        
        if ($mtime === false) {
            continue;
        }
        
        // Try to get metadata from companion file
        $metaFile = $file . '.meta';
        $user = 'unknown';
        
        if (file_exists($metaFile)) {
            $meta = json_decode(file_get_contents($metaFile), true);
            if (is_array($meta) && isset($meta['user'])) {
                $user = $meta['user'];
            }
        }
        
        $changes[] = [
            'page' => $pageName,
            'timestamp' => $mtime,
            'user' => $user,
            'date' => date('Y-m-d H:i:s', $mtime)
        ];
    }
    
    // Sort by timestamp descending (newest first)
    usort($changes, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });
    
    return array_slice($changes, 0, $limit);
}

/**
 * Save page metadata (user, timestamp)
 * 
 * @param string $pagePath Full path to the page file
 * @param string $user Username who made the edit
 * @return bool Success status
 */
function savePageMetadata(string $pagePath, string $user): bool
{
    $metaFile = $pagePath . '.meta';
    $metadata = [
        'user' => $user,
        'timestamp' => time(),
        'date' => date('Y-m-d H:i:s')
    ];
    
    $result = file_put_contents($metaFile, json_encode($metadata, JSON_PRETTY_PRINT), LOCK_EX);
    
    if ($result !== false) {
        chmod($metaFile, 0644);
        return true;
    }
    
    return false;
}
