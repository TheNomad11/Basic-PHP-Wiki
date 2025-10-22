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

// Require Parsedown
require_once 'Parsedown.php';

// Start session with hardened cookie params
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.save_path', SESSIONS_DIR);
    if (!is_dir(SESSIONS_DIR)) {
        @mkdir(SESSIONS_DIR, 0750, true);
    }
    
    $cookieParams = [
        'lifetime' => SESSION_LIFETIME,
        'path' => '/',
        'domain' => '',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax'
    ];
    session_set_cookie_params($cookieParams);
    session_start();
}

// Rest of your functions...


// -----------------------------
// Utility: Logging
// -----------------------------
function logMessage(string $message, string $level = 'INFO', string $logFile = LOG_FILE): void
{
    if (empty($logFile)) {
        return;
    }

    $timestamp = gmdate('Y-m-d H:i:s'); // use UTC for logs
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $logEntry = "[$timestamp] [$level] [$ip] $message\n";

    $dir = dirname($logFile);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    $fh = @fopen($logFile, 'a');
    if ($fh) {
        if (flock($fh, LOCK_EX)) {
            fwrite($fh, $logEntry);
            fflush($fh);
            flock($fh, LOCK_UN);
        }
        fclose($fh);
    }
}

// -----------------------------
// Utility: safe client IP
// -----------------------------
function getClientIp(): string
{
    if (TRUST_PROXY) {
        // Only trust proxy headers if you explicitly configured TRUST_PROXY = true
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
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

    $fh = @fopen($file, 'c+');
    if (!$fh) {
        return [];
    }

    $data = [];
    if (flock($fh, LOCK_SH)) {
        clearstatcache(true, $file);
        $contents = stream_get_contents($fh);
        $data = json_decode($contents ?: '{}', true) ?? [];
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    return $data;
}

function writeJsonFileLocked(string $file, array $data): bool
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0750, true)) {
            return false;
        }
    }

    $tmp = $file . '.tmp';
    $fh = @fopen($tmp, 'c');
    if (!$fh) return false;

    if (!flock($fh, LOCK_EX)) {
        fclose($fh);
        @unlink($tmp);
        return false;
    }

    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    // atomic rename
    return @rename($tmp, $file);
}

// -----------------------------
// Rate limit functions (use locked helpers)
// -----------------------------
function checkRateLimit(string $ip, string $rateLimitFile = RATE_LIMIT_FILE, int $maxAttempts = RATE_MAX_ATTEMPTS, int $blockDuration = RATE_BLOCK_SECONDS): bool
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    $now = time();

    // cleanup expired entries
    foreach ($rateLimits as $k => $v) {
        if (!isset($v['first']) || ($now - (int)$v['first']) > $blockDuration) {
            unset($rateLimits[$k]);
        }
    }

    if (!isset($rateLimits[$ip])) {
        $rateLimits[$ip] = ['count' => 0, 'first' => $now];
    }

    $entry = $rateLimits[$ip];

    if (($entry['count'] ?? 0) >= $maxAttempts) {
        $elapsed = $now - (int)$entry['first'];
        if ($elapsed < $blockDuration) {
            // still blocked
            return false;
        } else {
            // reset window
            $rateLimits[$ip] = ['count' => 0, 'first' => $now];
        }
    }

    // write back (we do not increment here; increment occurs on failure)
    writeJsonFileLocked($rateLimitFile, $rateLimits);
    return true;
}

function recordFailedAttempt(string $ip, string $rateLimitFile = RATE_LIMIT_FILE): void
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    $now = time();

    if (!isset($rateLimits[$ip]) || ($now - (int)$rateLimits[$ip]['first']) > RATE_BLOCK_SECONDS) {
        $rateLimits[$ip] = ['count' => 1, 'first' => $now];
    } else {
        $rateLimits[$ip]['count'] = ($rateLimits[$ip]['count'] ?? 0) + 1;
    }

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
    if (empty($stored) || empty($token)) return false;
    return hash_equals($stored, $token);
}

// -----------------------------
// Image upload handler (re-encode using GD, safe filename, .htaccess)
// -----------------------------
function ensureUploadsDir(string $uploadsDir = UPLOADS_DIR): void
{
    if (!is_dir($uploadsDir)) {
        @mkdir($uploadsDir, 0755, true);
    }
    // create a minimal .htaccess to prevent script execution on Apache (harmless if server ignores it)
    $htaccess = $uploadsDir . '/.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess,
            "Options -Indexes\n<FilesMatch \"\\.(php|phtml|php3|phps)$\">\n    Deny from all\n</FilesMatch>\n", LOCK_EX);
    }
    // for nginx, advise server config (can't modify here reliably)
}

function handleImageUpload(array $file, string $uploadsDir = UPLOADS_DIR, int $maxSize = MAX_UPLOAD_SIZE): array
{
    ensureUploadsDir($uploadsDir);

    // Basic checks
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'Upload error occurred'];
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return ['success' => false, 'message' => 'Possible file upload attack'];
    }
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large (max ' . round($maxSize/1024/1024, 1) . 'MB)'];
    }

    // Validate it's an image
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['success' => false, 'message' => 'File is not a valid image'];
    }
    [$width, $height, $imageType] = [$imageInfo[0], $imageInfo[1], $imageInfo[2]];

    if ($width > MAX_IMAGE_WIDTH || $height > MAX_IMAGE_HEIGHT) {
        return ['success' => false, 'message' => 'Image dimensions too large'];
    }

    // Check MIME type with finfo
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

    // Re-encode image with GD to strip metadata and ensure valid image
    $extension = $allowedMimes[$mimeType];
    $filename = date('Y-m-d_His') . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
    $targetPath = $uploadsDir . '/' . $filename;

    // create image resource depending on mime
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
        return ['success' => false, 'message' => 'Unsupported image or failed to process'];
    }

    // Optionally resize if extremely large (avoid memory issues)
    $maxDim = 8000;
    if ($width > $maxDim || $height > $maxDim) {
        $ratio = min($maxDim / $width, $maxDim / $height);
        $newW = (int)($width * $ratio);
        $newH = (int)($height * $ratio);
        $tmpImg = imagecreatetruecolor($newW, $newH);
        imagecopyresampled($tmpImg, $srcImg, 0, 0, 0, 0, $newW, $newH, $width, $height);
        imagedestroy($srcImg);
        $srcImg = $tmpImg;
    }

    // Save re-encoded image
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
            } else {
                // fallback to png
                $targetPath = preg_replace('/\.webp$/', '.png', $targetPath);
                $saved = imagepng($srcImg, $targetPath, 6);
            }
            break;
    }
    imagedestroy($srcImg);

    if (!$saved) {
        return ['success' => false, 'message' => 'Failed to save processed image'];
    }

    chmod($targetPath, 0644);
    // success
    return ['success' => true, 'filename' => $filename];
}

// -----------------------------
// Markdown parsing & sanitization
// Using Parsedown in safe mode + careful post-processing
// -----------------------------
function sanitizeTextForAttr(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function parseMarkdown(string $text): string
{
 
 // Pre-process wikilinks
 
 function preprocessWikiLinks(string $text): string {
    return preg_replace_callback('/\[\[([^\]]+)\]\]/', function($m) {
        $page = trim($m[1]);
        $safePage = rawurlencode($page);
        // Markdown link: [Page](?page=Page)
        return '[' . htmlspecialchars($page, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '](?page=' . $safePage . ')';
    }, $text);
}

 
    // Pre-process hashtags -> safe anchor (we will HTML-encode tag text)
    $text = preg_replace_callback('/(^|\s)#([a-zA-Z0-9_\-]+)/', function($m) {
        $prefix = $m[1];
        $tag = $m[2];
        return $prefix . '[#' . $tag . '](' . '?tag=' . rawurlencode($tag) . ')';
    }, $text);

    // Pre-process wiki links already in the format [[Page]] will be left for Parsedown to render as links later via our callback.
    // Process custom image modifiers notation: convert to title marker for later safe post-processing
    $text = preg_replace_callback('/!\[([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/', function($m) {
        $alt = $m[1];
        $url = $m[2];
        $modifiers = $m[3];
        // Escape quotes in title
        $safeModifiers = str_replace('"', '&quot;', $modifiers);
        return '![' . $alt . '](' . $url . ' "IMGMOD:' . $safeModifiers . '")';
    }, $text);

    // Use Parsedown safe mode (disallow raw HTML)
    $text = preprocessWikiLinks($text);
    $parsedown = new Parsedown();
    $parsedown->setSafeMode(true);
    $html = $parsedown->text($text);

    // Post-process: convert our special tag link format [#tag](?tag=...) back to anchor with safe-escaped text
    $html = preg_replace_callback('/<a href="([^"]+)">#([^<]+)<\/a>/', function($m) {
        $href = sanitizeTextForAttr($m[1]);
        $tag  = htmlspecialchars($m[2], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return '<a href="' . $href . '" class="tag">#' . $tag . '</a>';
    }, $html);

    // Post-process internal wiki links [[Page]] inserted by autoLink logic may already be present in raw text.
    // Parsedown escapes bracket sequences but because safe mode is on, any embedded link will be plain anchor from markdown.
    // For images with title IMGMOD: we replace only title attribute content carefully
    $html = preg_replace_callback('/<img([^>]*)title="IMGMOD:([^"]+)"([^>]*)>/i', function($m) {
        $before = $m[1];
        $modifiers = $m[2];
        $after = $m[3];

        // parse modifiers for classes like .rounded .small etc.
        $classes = [];
        if (preg_match_all('/\.(\w[\w-]*)/', $modifiers, $cmatches)) {
            foreach ($cmatches[1] as $c) {
                $classes[] = 'img-' . htmlspecialchars($c, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            }
        }
        $classAttr = $classes ? ' class="' . implode(' ', $classes) . '"' : '';
        $style = ' style="max-width:100%; max-height:400px;"';
        // Rebuild tag without the title attribute and with safe class/style
        return '<img' . $before . $classAttr . $style . $after . '>';
    }, $html);

    // Ensure images without style get style attribute; handle common attribute orders
    $html = preg_replace_callback('/<img((?:(?!style=)[^>])*)>/i', function($m) {
        $attrs = $m[1];
        // don't duplicate if style already present
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
    static $cached = null;
    if ($cached !== null) return $cached;

    $pages = [];
    if (!is_dir($pagesDir)) {
        @mkdir($pagesDir, 0755, true);
    }
    $files = glob($pagesDir . '/*.md');
    if ($files !== false) {
        foreach ($files as $f) {
            $pages[] = basename($f, '.md');
        }
    }
    // sort longest first to avoid partial matches
    usort($pages, function($a, $b) { return strlen($b) - strlen($a); });
    $cached = $pages;
    return $pages;
}

function safePageName(string $name): string
{
    // allow letters, numbers, spaces, underscores, hyphens; trim and collapse whitespace
    $name = preg_replace('/[^\p{L}\p{N} _\-]/u', '', $name);
    $name = preg_replace('/\s+/', ' ', trim($name));
    if ($name === '') return 'Home';
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
        }, $text);
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
// Backlinks & related pages
// -----------------------------
function getBacklinks(string $currentPage, string $pagesDir = PAGES_DIR): array
{
    $backlinks = [];
    if (!is_dir($pagesDir)) return $backlinks;
    $files = glob($pagesDir . '/*.md');
    if ($files === false) return $backlinks;

    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        if (strcasecmp($pageName, $currentPage) === 0) continue;
        $content = @file_get_contents($file);
        if ($content === false) continue;
        if (preg_match('/\[\[' . preg_quote($currentPage, '/') . '\]\]/i', $content)) {
            $backlinks[] = $pageName;
        }
    }
    return $backlinks;
}

function getRelatedPagesByTags(string $currentPage, string $content, string $pagesDir = PAGES_DIR, int $limit = 5): array
{
    preg_match_all('/#([a-zA-Z0-9_\-]+)/', $content, $m);
    $currentTags = $m[1] ?? [];
    if (empty($currentTags)) return [];

    $related = [];
    $files = glob($pagesDir . '/*.md');
    if ($files === false) return [];

    foreach ($files as $file) {
        $pageName = basename($file, '.md');
        if (strcasecmp($pageName, $currentPage) === 0) continue;
        $otherContent = @file_get_contents($file);
        if ($otherContent === false) continue;
        preg_match_all('/#([a-zA-Z0-9_\-]+)/', $otherContent, $om);
        $otherTags = $om[1] ?? [];
        $shared = array_intersect($currentTags, $otherTags);
        if (count($shared) > 0) {
            $related[$pageName] = ['count' => count($shared), 'tags' => $shared];
        }
    }
    uasort($related, function($a, $b) { return $b['count'] - $a['count']; });
    return array_slice($related, 0, $limit, true);
}

// -----------------------------
// Security headers (CSP with nonce + others)
// -----------------------------
function sendSecurityHeaders(string $nonce): void
{
    // CSP: allow scripts from self + nonce only; adjust as needed
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer-when-downgrade');
    // HSTS only when HTTPS is certain in your deployment
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    }
}

// -----------------------------
// Nonce & rendering helpers
// -----------------------------
function generateNonce(): string
{
    // 16-byte random -> base64 url safe
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
        <?php if ($loggedIn): ?>
            <form method="post" style="display:inline;">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
                <button type="submit" name="logout">Logout (<?= $user ?>)</button>
            </form>
        <?php endif; ?>
        <form method="get" style="display:inline;">
            <input type="text" name="q" placeholder="Search" value="<?= $searchVal ?>" maxlength="100">
            <button type="submit" name="search">🔍</button>
        </form>
    </nav>
    <?php
}

function renderPage(string $title, callable $contentCallback, string $nonce = ''): void
{
    // send headers early
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



// -----------------------------
// End of library file - usage:
// - Use parseMarkdownWithAutoLink(...) to render page contents securely.
// - Use safePageName($_GET['page']) before reading files.
// - Provide CSRF token via generateCsrfToken() in forms.
// - Serve uploads from UPLOADS_DIR via controlled script or adjust server config.
// -----------------------------
