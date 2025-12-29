<?php
declare(strict_types=1);

// Load configuration
$config = require __DIR__ . '/config.php';

// Define constants from config
define('PAGES_DIR', $config['pages_dir']);
define('UPLOADS_DIR', $config['uploads_dir']);
define('SESSIONS_DIR', $config['sessions_dir'] ?? __DIR__ . '/sessions');
define('USERS_FILE', $config['users_file'] ?? __DIR__ . '/users.json.php');
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
define('SEARCH_RESULTS_PER_PAGE', 20);
define('PAGE_LIST_CACHE_TIME', 300);
define('MAX_REVISIONS', $config['max_revisions'] ?? 10);

require_once 'Parsedown.php';

$_pageNamesCache = null;
$_pageNamesCacheTime = 0;

function validatePageName(string $pageName): ?string
{
    $pageName = str_replace(['/', '\\', "\0"], '', $pageName);
    $pageName = str_replace(['..', '~'], '', $pageName);
    $pageName = preg_replace('/[^\p{L}\p{N} _\-]/u', '', $pageName);
    $pageName = preg_replace('/\s+/', ' ', trim($pageName));
    if (strlen($pageName) > MAX_PAGE_NAME_LENGTH || strlen($pageName) < 1) {
        return null;
    }
    return $pageName;
}

function validateFilePath(string $filePath, string $baseDir): bool
{
    $realBase = realpath($baseDir);
    if ($realBase === false) {
        return false;
    }
    if (!file_exists($filePath)) {
        $parentDir = dirname($filePath);
        if (!file_exists($parentDir)) {
            $parentDir = $baseDir;
        }
        $realPath = realpath($parentDir);
    } else {
        $realPath = realpath($filePath);
    }
    return $realPath !== false && strpos($realPath, $realBase) === 0;
}

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
    $fh = @fopen($logFile, 'a');
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

function readProtectedJsonFile(string $file): array
{
    if (!file_exists($file)) {
        return [];
    }
    $content = @file_get_contents($file);
    if ($content === false) {
        return [];
    }
    $content = preg_replace('/^<\?php[^?]*\?>\s*/s', '', $content);
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

function writeProtectedJsonFile(string $file, array $data): bool
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true) && !is_dir($dir)) {
            logMessage("Failed to create directory: $dir", 'ERROR');
            return false;
        }
    }
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        logMessage("Failed to encode JSON for file: $file", 'ERROR');
        return false;
    }
    $protected = "<?php http_response_code(403); die('Access denied'); ?>\n" . $json;
    $result = @file_put_contents($file, $protected, LOCK_EX);
    if ($result !== false) {
        @chmod($file, 0600);
        return true;
    }
    logMessage("Failed to write protected JSON file: $file", 'ERROR');
    return false;
}

function loadUsersFile(string $usersFile = USERS_FILE): array
{
    if (!file_exists($usersFile)) {
        return [];
    }
    $content = @file_get_contents($usersFile);
    if ($content === false) {
        logMessage("Failed to read users file: $usersFile", 'ERROR');
        return [];
    }
    $content = preg_replace('/^<\?php[^?]*\?>\s*/s', '', $content);
    $users = json_decode($content, true);
    if (!is_array($users)) {
        logMessage("Invalid users file format: $usersFile", 'ERROR');
        return [];
    }
    return $users;
}

function readJsonFileLocked(string $file): array
{
    if (!file_exists($file)) {
        return [];
    }
    $fh = @fopen($file, 'r');
    if ($fh === false) {
        logMessage("Failed to open file for reading: $file", 'ERROR');
        return [];
    }
    $data = [];
    if (flock($fh, LOCK_SH)) {
        $contents = stream_get_contents($fh);
        if ($contents !== false) {
            $contents = preg_replace('/^<\?php[^?]*\?>\s*/s', '', $contents);
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
    $tmp = $file . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
    $lockFile = $dir . '/.lock';
    $lockFh = @fopen($lockFile, 'c');
    if ($lockFh === false) {
        logMessage("Failed to create lock file: $lockFile", 'ERROR');
        return false;
    }
    if (!flock($lockFh, LOCK_EX)) {
        fclose($lockFh);
        logMessage("Failed to acquire lock: $lockFile", 'ERROR');
        return false;
    }
    try {
        $fh = @fopen($tmp, 'w');
        if ($fh === false) {
            throw new Exception("Failed to create temp file: $tmp");
        }
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            fclose($fh);
            throw new Exception("Failed to encode JSON");
        }
        if (substr($file, -4) === '.php') {
            $json = "<?php http_response_code(403); die('Access denied'); ?>\n" . $json;
        }
        if (fwrite($fh, $json) === false) {
            fclose($fh);
            throw new Exception("Failed to write to temp file");
        }
        if (!fflush($fh)) {
            fclose($fh);
            throw new Exception("Failed to flush temp file");
        }
        fclose($fh);
        if (!rename($tmp, $file)) {
            throw new Exception("Failed to rename temp file to: $file");
        }
        @chmod($file, 0600);
        flock($lockFh, LOCK_UN);
        fclose($lockFh);
        return true;
    } catch (Exception $e) {
        logMessage($e->getMessage(), 'ERROR');
        if (file_exists($tmp)) {
            @unlink($tmp);
        }
        flock($lockFh, LOCK_UN);
        fclose($lockFh);
        return false;
    }
}

function checkRateLimit(string $identifier, string $rateLimitFile = RATE_LIMIT_FILE, int $maxAttempts = RATE_MAX_ATTEMPTS, int $blockDuration = RATE_BLOCK_SECONDS): bool
{
    $rateLimits = readJsonFileLocked($rateLimitFile);
    $now = time();
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

function saveRevision(string $pageName, string $content, string $user): bool
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        logMessage("Invalid page name in saveRevision: $pageName", 'ERROR');
        return false;
    }
    $pagesDir = PAGES_DIR;
    $timestamp = time();
    $revisionFile = $pagesDir . '/' . $validatedName . '.md.rev.' . $timestamp;
    if (!validateFilePath($revisionFile, $pagesDir)) {
        logMessage("Invalid file path in saveRevision: $revisionFile", 'ERROR');
        return false;
    }
    $result = @file_put_contents($revisionFile, $content, LOCK_EX);
    if ($result === false) {
        logMessage("Failed to save revision for: $validatedName", 'ERROR');
        return false;
    }
    @chmod($revisionFile, 0644);
    $metaFile = $revisionFile . '.meta';
    $metadata = [
        'user' => $user,
        'timestamp' => $timestamp,
        'date' => date('Y-m-d H:i:s', $timestamp)
    ];
    @file_put_contents($metaFile, json_encode($metadata, JSON_PRETTY_PRINT), LOCK_EX);
    @chmod($metaFile, 0644);
    cleanupOldRevisions($validatedName);
    return true;
}

function getRevisions(string $pageName): array
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        logMessage("Invalid page name in getRevisions: $pageName", 'ERROR');
        return [];
    }
    $pagesDir = PAGES_DIR;
    $pattern = $pagesDir . '/' . $validatedName . '.md.rev.*';
    $files = glob($pattern);
    if ($files === false) {
        return [];
    }
    $revisions = [];
    foreach ($files as $file) {
        if (strpos($file, '.meta') !== false) {
            continue;
        }
        if (!validateFilePath($file, $pagesDir)) {
            logMessage("Invalid file path in getRevisions: $file", 'ERROR');
            continue;
        }
        if (preg_match('/\.md\.rev\.(\d+)$/', $file, $matches)) {
            $timestamp = (int)$matches[1];
            $metaFile = $file . '.meta';
            $user = 'unknown';
            if (file_exists($metaFile)) {
                $meta = json_decode(@file_get_contents($metaFile), true);
                if (is_array($meta) && isset($meta['user'])) {
                    $user = $meta['user'];
                }
            }
            $revisions[] = [
                'timestamp' => $timestamp,
                'date' => date('Y-m-d H:i:s', $timestamp),
                'user' => $user,
                'file' => $file
            ];
        }
    }
    usort($revisions, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });
    return $revisions;
}

function getRevisionContent(string $pageName, int $timestamp): ?string
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        return null;
    }
    $pagesDir = PAGES_DIR;
    $revisionFile = $pagesDir . '/' . $validatedName . '.md.rev.' . $timestamp;
    if (!validateFilePath($revisionFile, $pagesDir)) {
        logMessage("Invalid file path in getRevisionContent: $revisionFile", 'ERROR');
        return null;
    }
    if (!file_exists($revisionFile)) {
        return null;
    }
    $content = @file_get_contents($revisionFile);
    return $content !== false ? $content : null;
}

function restoreRevision(string $pageName, int $timestamp, string $user): bool
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        logMessage("Invalid page name in restoreRevision: $pageName", 'ERROR');
        return false;
    }
    $pagesDir = PAGES_DIR;
    $pageFile = $pagesDir . '/' . $validatedName . '.md';
    $revisionFile = $pagesDir . '/' . $validatedName . '.md.rev.' . $timestamp;
    if (!validateFilePath($pageFile, $pagesDir) || !validateFilePath($revisionFile, $pagesDir)) {
        logMessage("Invalid file path in restoreRevision", 'ERROR');
        return false;
    }
    if (!file_exists($revisionFile)) {
        logMessage("Revision not found: $revisionFile", 'ERROR');
        return false;
    }
    $revisionContent = @file_get_contents($revisionFile);
    if ($revisionContent === false) {
        logMessage("Failed to read revision: $revisionFile", 'ERROR');
        return false;
    }
    if (file_exists($pageFile)) {
        $currentContent = @file_get_contents($pageFile);
        if ($currentContent !== false && $currentContent !== $revisionContent) {
            saveRevision($validatedName, $currentContent, $user);
        }
    }
    $result = @file_put_contents($pageFile, $revisionContent, LOCK_EX);
    if ($result === false) {
        logMessage("Failed to restore revision to: $pageFile", 'ERROR');
        return false;
    }
    @chmod($pageFile, 0644);
    savePageMetadata($pageFile, $user);
    clearAllPageCaches();
    logMessage("Restored revision for: $validatedName (timestamp: $timestamp)", 'INFO');
    return true;
}

function cleanupOldRevisions(string $pageName): void
{
    $revisions = getRevisions($pageName);
    if (count($revisions) <= MAX_REVISIONS) {
        return;
    }
    $toDelete = array_slice($revisions, MAX_REVISIONS);
    foreach ($toDelete as $rev) {
        if (isset($rev['file']) && file_exists($rev['file'])) {
            @unlink($rev['file']);
            $metaFile = $rev['file'] . '.meta';
            if (file_exists($metaFile)) {
                @unlink($metaFile);
            }
        }
    }
}

function generateDiff(string $old, string $new): array
{
    $oldLines = explode("\n", $old);
    $newLines = explode("\n", $new);
    $diff = [];
    $maxLines = max(count($oldLines), count($newLines));
    for ($i = 0; $i < $maxLines; $i++) {
        $oldLine = $oldLines[$i] ?? '';
        $newLine = $newLines[$i] ?? '';
        if ($oldLine === $newLine) {
            $diff[] = ['type' => 'unchanged', 'content' => $oldLine];
        } elseif ($oldLine === '') {
            $diff[] = ['type' => 'added', 'content' => $newLine];
        } elseif ($newLine === '') {
            $diff[] = ['type' => 'removed', 'content' => $oldLine];
        } else {
            $diff[] = ['type' => 'removed', 'content' => $oldLine];
            $diff[] = ['type' => 'added', 'content' => $newLine];
        }
    }
    return $diff;
}

function getRevisionMetadata(string $pageName, int $timestamp): ?array
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        return null;
    }
    $pagesDir = PAGES_DIR;
    $revisionFile = $pagesDir . '/' . $validatedName . '.md.rev.' . $timestamp;
    $metaFile = $revisionFile . '.meta';
    if (!file_exists($metaFile)) {
        return [
            'user' => 'unknown',
            'timestamp' => $timestamp,
            'date' => date('Y-m-d H:i:s', $timestamp)
        ];
    }
    $meta = json_decode(@file_get_contents($metaFile), true);
    return is_array($meta) ? $meta : null;
}

function deletePage(string $pageName, string $user): bool
{
    $validatedName = validatePageName($pageName);
    if ($validatedName === null) {
        logMessage("Invalid page name in deletePage: $pageName", 'ERROR');
        return false;
    }
    $protectedPages = ['Home', 'AllPages', 'AllTags', 'RecentChanges'];
    if (in_array($validatedName, $protectedPages)) {
        logMessage("Attempt to delete protected page: $validatedName by user: $user", 'WARNING');
        return false;
    }
    $pagesDir = PAGES_DIR;
    $pageFile = $pagesDir . '/' . $validatedName . '.md';
    if (!validateFilePath($pageFile, $pagesDir)) {
        logMessage("Invalid file path in deletePage: $pageFile", 'ERROR');
        return false;
    }
    if (!file_exists($pageFile)) {
        logMessage("Page not found for deletion: $pageFile", 'ERROR');
        return false;
    }
    $content = @file_get_contents($pageFile);
    if ($content !== false) {
        saveRevision($validatedName, $content, $user . ' (before deletion)');
    }
    if (!@unlink($pageFile)) {
        logMessage("Failed to delete page file: $pageFile", 'ERROR');
        return false;
    }
    $metaFile = $pageFile . '.meta';
    if (file_exists($metaFile)) {
        @unlink($metaFile);
    }
    $revisions = getRevisions($validatedName);
    foreach ($revisions as $rev) {
        if (isset($rev['file']) && file_exists($rev['file'])) {
            @unlink($rev['file']);
            $revMetaFile = $rev['file'] . '.meta';
            if (file_exists($revMetaFile)) {
                @unlink($revMetaFile);
            }
        }
    }
    clearPageCache($validatedName);
    clearAllPageCaches();
    @touch(CACHE_DIR . '/.rebuild_index');
    logMessage("Page deleted: $validatedName by user: $user", 'INFO');
    return true;
}

function getDeletablePages(string $pagesDir = PAGES_DIR): array
{
    $allPages = getAllPageNames($pagesDir);
    $protectedPages = ['Home', 'AllPages', 'AllTags', 'RecentChanges'];
    return array_filter($allPages, function($page) use ($protectedPages) {
        return !in_array($page, $protectedPages);
    });
}

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

function generateCsrfToken(): string
{
    if (empty($_SESSION['csrf_token']) || empty($_SESSION['csrf_token_time'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    if (time() - $_SESSION['csrf_token_time'] > 3600) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(?string $token): bool
{
    $stored = $_SESSION['csrf_token'] ?? '';
    $tokenTime = $_SESSION['csrf_token_time'] ?? 0;
    if (empty($stored) || empty($token)) {
        return false;
    }
    if (time() - $tokenTime > 7200) {
        return false;
    }
    return hash_equals($stored, $token);
}

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
        if (@file_put_contents($htaccess, $content, LOCK_EX) === false) {
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
    $filename = date('Y-m-d_His') . '_' . bin2hex(random_bytes(12)) . '.' . $extension;
    $targetPath = $uploadsDir . '/' . $filename;
    $counter = 0;
    while (file_exists($targetPath) && $counter < 10) {
        $filename = date('Y-m-d_His') . '_' . bin2hex(random_bytes(12)) . '.' . $extension;
        $targetPath = $uploadsDir . '/' . $filename;
        $counter++;
    }
    if (file_exists($targetPath)) {
        return ['success' => false, 'message' => 'Failed to generate unique filename'];
    }
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
    @chmod($targetPath, 0644);
    return ['success' => true, 'filename' => $filename];
}

function cleanContentForTags(string $content): string
{
    $lines = explode("\n", $content);
    $cleanedLines = [];
    $inCodeBlock = false;
    $codeBlockDelimiter = '';
    foreach ($lines as $line) {
        if (preg_match('/^\s*(```|~~~)/', $line, $matches)) {
            if (!$inCodeBlock) {
                $inCodeBlock = true;
                $codeBlockDelimiter = $matches[1];
            } elseif ($matches[1] === $codeBlockDelimiter) {
                $inCodeBlock = false;
                $codeBlockDelimiter = '';
            }
            continue;
        }
        if ($inCodeBlock) {
            continue;
        }
        if (preg_match('/^\s*#{1,6}\s/', $line)) {
            continue;
        }
        if (preg_match('/^\s{4,}/', $line)) {
            continue;
        }
        $cleanedLines[] = $line;
    }
    $cleaned = implode("\n", $cleanedLines);
    $cleaned = preg_replace('/`[^`]+`/', '', $cleaned);
    $cleaned = preg_replace('/\[([^\]]+)\]\([^\)]+\)/', '$1', $cleaned);
    return $cleaned;
}

function extractTags(string $content): array
{
    $cleaned = cleanContentForTags($content);
    if (preg_match_all('/(?:^|\s)#([a-zA-Z0-9_\-]+)(?:\s|$)/m', $cleaned, $matches)) {
        return array_unique($matches[1]);
    }
    return [];
}

function getAllTags(string $pagesDir = PAGES_DIR, int $maxTagLength = MAX_TAG_LENGTH): array
{
    $allTags = [];
    $files = glob($pagesDir . '/*.md');
    if ($files === false) {
        return [];
    }
    foreach ($files as $filename) {
        if (strpos($filename, '.md.rev.') !== false) {
            continue;
        }
        if (!validateFilePath($filename, $pagesDir)) {
            continue;
        }
        $content = @file_get_contents($filename);
        if ($content === false) {
            continue;
        }
        $tags = extractTags($content);
        foreach ($tags as $tag) {
            if (strlen($tag) <= $maxTagLength) {
                $allTags[$tag] = true;
            }
        }
    }
    $allTags = array_keys($allTags);
    sort($allTags, SORT_NATURAL | SORT_FLAG_CASE);
    return $allTags;
}

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
    $text = preg_replace_callback('/(^|\s)#([a-zA-Z0-9_\-]+)/', function($m) {
        $prefix = $m[1];
        $tag = $m[2];
        return $prefix . '[#' . $tag . '](' . '?tag=' . rawurlencode($tag) . ')';
    }, $text);
    $text = preprocessWikiLinks($text);
    $text = preg_replace_callback('/!\[([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/', function($m) {
        $alt = $m[1];
        $url = $m[2];
        $modifiers = $m[3];
        $safeModifiers = str_replace('"', '&quot;', $modifiers);
        return '![' . $alt . '](' . $url . ' "IMGMOD:' . $safeModifiers . '")';
    }, $text);
    $parsedown = new Parsedown();
    $parsedown->setSafeMode(true);
    $html = $parsedown->text($text);
    $html = preg_replace_callback('/<a href="([^"]+)">#([^<]+)<\/a>/', function($m) {
        $href = sanitizeTextForAttr($m[1]);
        $tag  = htmlspecialchars($m[2], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return '<a href="' . $href . '" class="tag">#' . $tag . '</a>';
    }, $html);
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
    $html = preg_replace_callback('/<img((?:(?!style=)[^>])*)>/i', function($m) {
        $attrs = $m[1];
        if (stripos($attrs, 'style=') !== false) {
            return '<img' . $attrs . '>';
        }
        return '<img' . $attrs . ' style="max-width:100%; max-height:400px;">';
    }, $html);
    return $html;
}

function getAllPageNames(string $pagesDir = PAGES_DIR): array
{
    global $_pageNamesCache, $_pageNamesCacheTime;
    if ($_pageNamesCache !== null && (time() - $_pageNamesCacheTime) < PAGE_LIST_CACHE_TIME) {
        return $_pageNamesCache;
    }
    $pages = [];
    if (!is_dir($pagesDir)) {
        if (!mkdir($pagesDir, 0755, true) && !is_dir($pagesDir)) {
            return [];
        }
    }
    $files = glob($pagesDir . '/*.md');
    if ($files !== false) {
        foreach ($files as $f) {
            if (strpos($f, '.md.rev.') !== false) {
                continue;
            }
            if (!validateFilePath($f, $pagesDir)) {
                continue;
            }
            $pages[] = basename($f, '.md');
        }
    }
    usort($pages, function($a, $b) { 
        return strlen($b) - strlen($a); 
    });
    $_pageNamesCache = $pages;
    $_pageNamesCacheTime = time();
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
    $currentHash = md5($content);
    $cachedHash = @file_get_contents($hashFile);
    if ($currentHash !== $cachedHash) {
        return null;
    }
    return @file_get_contents($cacheFile);
}

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
    $result1 = @file_put_contents($cacheFile, $html, LOCK_EX);
    $result2 = @file_put_contents($hashFile, $contentHash, LOCK_EX);
    if ($result1 !== false && $result2 !== false) {
        @chmod($cacheFile, 0644);
        @chmod($hashFile, 0644);
        return true;
    }
    return false;
}

function clearPageCache(string $pageName): void
{
    global $_pageNamesCache;
    $cacheDir = CACHE_DIR;
    $cacheFile = $cacheDir . '/' . md5($pageName) . '.html';
    $hashFile = $cacheFile . '.hash';
    if (file_exists($cacheFile)) {
        @unlink($cacheFile);
    }
    if (file_exists($hashFile)) {
        @unlink($hashFile);
    }
    $_pageNamesCache = null;
}

function clearAllPageCaches(): void
{
    global $_pageNamesCache;
    $cacheDir = CACHE_DIR;
    if (!is_dir($cacheDir)) {
        return;
    }
    $files = glob($cacheDir . '/*.html');
    if ($files !== false) {
        foreach ($files as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }
    }
    $hashFiles = glob($cacheDir . '/*.hash');
    if ($hashFiles !== false) {
        foreach ($hashFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }
    }
    $_pageNamesCache = null;
}

function buildSearchIndex(string $pagesDir = PAGES_DIR): bool
{
    $index = [];
    $files = glob($pagesDir . '/*.md');
    if ($files === false) {
        return false;
    }
    foreach ($files as $file) {
        if (strpos($file, '.md.rev.') !== false) {
            continue;
        }
        if (!validateFilePath($file, $pagesDir)) {
            continue;
        }
        $pageName = basename($file, '.md');
        $content = @file_get_contents($file);
        if ($content === false) {
            continue;
        }
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

function getSearchIndex(string $pagesDir = PAGES_DIR): array
{
    $indexFile = SEARCH_INDEX_FILE;
    if (file_exists($indexFile)) {
        $indexAge = time() - filemtime($indexFile);
        if ($indexAge < 3600) {
            return readJsonFileLocked($indexFile);
        }
    }
    buildSearchIndex($pagesDir);
    return readJsonFileLocked($indexFile);
}

function searchWithIndex(string $query, string $pagesDir = PAGES_DIR, int $limit = 100): array
{
    $index = getSearchIndex($pagesDir);
    $results = [];
    $queryLower = strtolower($query);
    foreach ($index as $pageName => $data) {
        if (count($results) >= $limit) {
            break;
        }
        if (stripos($data['name'], $query) !== false) {
            $results[$pageName] = '<mark>' . htmlspecialchars($data['name'], ENT_QUOTES, 'UTF-8') . '</mark> (name match)';
            continue;
        }
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

function getBacklinks(string $currentPage, string $pagesDir = PAGES_DIR, int $limit = 20): array
{
    $backlinks = [];
    if (!is_dir($pagesDir)) {
        return $backlinks;
    }
    $files = glob($pagesDir . '/*.md');
    if ($files === false) {
        return $backlinks;
    }
    $count = 0;
    foreach ($files as $file) {
        if (strpos($file, '.md.rev.') !== false) {
            continue;
        }
        if (!validateFilePath($file, $pagesDir)) {
            continue;
        }
        if ($count >= $limit) {
            break;
        }
        $pageName = basename($file, '.md');
        if (strcasecmp($pageName, $currentPage) === 0) {
            continue;
        }
        $content = @file_get_contents($file);
        if ($content === false) {
            continue;
        }
        if (preg_match('/\[\[' . preg_quote($currentPage, '/') . '\]\]/i', $content)) {
            $backlinks[] = $pageName;
            $count++;
        }
    }
    return $backlinks;
}

function getRelatedPagesByTags(string $currentPage, string $content, string $pagesDir = PAGES_DIR, int $limit = 5): array
{
    $currentTags = extractTags($content);
    if (empty($currentTags)) {
        return [];
    }
    $related = [];
    $files = glob($pagesDir . '/*.md');
    if ($files === false) {
        return [];
    }
    foreach ($files as $file) {
        if (strpos($file, '.md.rev.') !== false) {
            continue;
        }
        if (!validateFilePath($file, $pagesDir)) {
            continue;
        }
        $pageName = basename($file, '.md');
        if (strcasecmp($pageName, $currentPage) === 0) {
            continue;
        }
        $otherContent = @file_get_contents($file);
        if ($otherContent === false) {
            continue;
        }
        $otherTags = extractTags($otherContent);
        $shared = array_intersect($currentTags, $otherTags);
        if (count($shared) > 0) {
            $related[$pageName] = ['count' => count($shared), 'tags' => $shared];
        }
        if (count($related) >= $limit * 3) {
            break;
        }
    }
    uasort($related, function($a, $b) { 
        return $b['count'] - $a['count']; 
    });
    return array_slice($related, 0, $limit, true);
}

function sendSecurityHeaders(string $nonce): void
{
    $csp = implode('; ', [
        "default-src 'self'",
        "script-src 'self' 'nonce-$nonce'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "media-src 'self'",
        "object-src 'none'",
        "frame-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ]);
    header("Content-Security-Policy: $csp");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('X-XSS-Protection: 1; mode=block');
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    }
}

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
        <a href="?manage=pages">Manage Pages</a>
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

function validateUserPasswords(string $usersFile = USERS_FILE): array
{
    $users = loadUsersFile($usersFile);
    $invalid = [];
    foreach ($users as $username => $hash) {
        $info = password_get_info($hash);
        if ($info['algo'] === null) {
            $invalid[] = $username;
        }
    }
    return $invalid;
}

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
        if (strpos($file, '.md.rev.') !== false) {
            continue;
        }
        if (!validateFilePath($file, $pagesDir)) {
            continue;
        }
        $pageName = basename($file, '.md');
        $mtime = filemtime($file);
        if ($mtime === false) {
            continue;
        }
        $metaFile = $file . '.meta';
        $user = 'unknown';
        if (file_exists($metaFile)) {
            $meta = json_decode(@file_get_contents($metaFile), true);
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
    usort($changes, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });
    return array_slice($changes, 0, $limit);
}

function savePageMetadata(string $pagePath, string $user): bool
{
    $metaFile = $pagePath . '.meta';
    $metadata = [
        'user' => $user,
        'timestamp' => time(),
        'date' => date('Y-m-d H:i:s')
    ];
    $result = @file_put_contents($metaFile, json_encode($metadata, JSON_PRETTY_PRINT), LOCK_EX);
    if ($result !== false) {
        @chmod($metaFile, 0644);
        return true;
    }
    return false;
}
