<?php
declare(strict_types=1);

// Load configuration FIRST
$config = require __DIR__ . '/config.php';

// Include functions
require_once __DIR__ . '/functions.php';


// Protection layer
require_once __DIR__ . '/protect.php';



// --- Start session with hardened settings ---
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.save_path', SESSIONS_DIR);
    if (!is_dir(SESSIONS_DIR)) {
        if (!mkdir(SESSIONS_DIR, 0750, true) && !is_dir(SESSIONS_DIR)) {
            die("Failed to create session directory");
        }
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

// Regenerate session ID on first visit
if (!isset($_SESSION['init'])) {
    session_regenerate_id(true);
    $_SESSION['init'] = true;
    $_SESSION['created'] = time();
}

// Generate CSP nonce
$nonce = generateNonce();

// --- Security Headers ---
header('Content-Type: text/html; charset=utf-8');
sendSecurityHeaders($nonce);
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Extract config
$pagesDir = $config['pages_dir'];
$uploadsDir = $config['uploads_dir'];
$sessionPath = $config['sessions_dir'];
$usersFile = $config['users_file'];
$rateLimitFile = $config['rate_limit_file'];
$logFile = $config['log_file'];
$defaultPage = $config['default_page'];
$enableAutoLink = $config['enable_auto_link'];

// Ensure pages directory exists
if (!is_dir($pagesDir)) {
    if (!mkdir($pagesDir, 0755, true) && !is_dir($pagesDir)) {
        die("Failed to create pages directory");
    }
    
    $indexFile = $pagesDir . '/Home.md';
    if (!file_exists($indexFile)) {
        file_put_contents($indexFile, "# Welcome to Simple Wiki\n\nEdit this page to get started.", LOCK_EX);
        chmod($indexFile, 0644);
    }
}

// Ensure cache directory exists
if (!is_dir(CACHE_DIR)) {
    if (!mkdir(CACHE_DIR, 0750, true) && !is_dir(CACHE_DIR)) {
        logMessage("Failed to create cache directory", 'ERROR', $logFile);
    }
}

// Check if search index needs rebuilding
$rebuildMarker = CACHE_DIR . '/.rebuild_index';
if (file_exists($rebuildMarker)) {
    buildSearchIndex($pagesDir);
    unlink($rebuildMarker);
}

// Session timeout (absolute timeout)
if (isset($_SESSION['created']) && (time() - $_SESSION['created'] > $config['session_lifetime'])) {
    session_unset();
    session_destroy();
    clearSessionCookie();
    header("Location: index.php");
    exit;
}

// Activity timeout
if (isset($_SESSION['loggedin']) && isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > $config['session_timeout']) {
        $username = $_SESSION['user'] ?? 'unknown';
        logMessage("Session timeout for user: $username", 'INFO', $logFile);
        session_unset();
        session_destroy();
        clearSessionCookie();
        header("Location: index.php");
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// Load users - UPDATED to use new function
$users = loadUsersFile($usersFile);
if (!empty($users)) {
    $invalid = validateUserPasswords($usersFile);
    if (!empty($invalid)) {
        logMessage("Found users with invalid password hashes: " . implode(', ', $invalid), 'CRITICAL', $logFile);
    }
}

// --- Handle login with rate limiting ---
$error = '';
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    if (!validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage('CSRF token mismatch on login', 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }

    $clientIp = getClientIp();
    
    if (!checkRateLimit($clientIp, $rateLimitFile, $config['max_login_attempts'], $config['login_block_duration'])) {
        $minutesRemaining = ceil($config['login_block_duration'] / 60);
        logMessage("Rate limit exceeded for IP: $clientIp", 'WARNING', $logFile);
        http_response_code(429);
        die("Too many failed login attempts. Please try again in $minutesRemaining minutes.");
    }
    
    $username = $_POST['username'];
    if (!preg_match('/^[a-zA-Z0-9_\-]{3,30}$/', $username)) {
        $error = "Invalid username format.";
        logMessage("Invalid username format attempted: $username from IP: $clientIp", 'WARNING', $logFile);
        recordFailedAttempt($clientIp, $rateLimitFile);
    } else {
        if (isset($users[$username]) && password_verify($_POST['password'], $users[$username])) {
            session_regenerate_id(true);
            $_SESSION['loggedin'] = true;
            $_SESSION['user'] = $username;
            $_SESSION['last_activity'] = time();
            resetRateLimit($clientIp, $rateLimitFile);
            logMessage("Successful login: $username from IP: $clientIp", 'INFO', $logFile);
            header("Location: index.php");
            exit;
        } else {
            recordFailedAttempt($clientIp, $rateLimitFile);
            $error = "Incorrect username or password.";
            logMessage("Failed login attempt for username: $username from IP: $clientIp", 'WARNING', $logFile);
            sleep(2);
        }
    }
}

// --- Handle logout ---
if (isset($_GET['logout']) || isset($_POST['logout'])) {
    if (isset($_POST['logout']) && !validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage('CSRF token mismatch on logout', 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }
    
    $username = $_SESSION['user'] ?? 'unknown';
    $clientIp = getClientIp();
    logMessage("User logout: $username from IP: $clientIp", 'INFO', $logFile);
    
    session_unset();
    session_destroy();
    clearSessionCookie();
    
    header("Location: index.php");
    exit;
}

// --- Require login ---
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login Required - Simple Wiki</title>
    <link rel="stylesheet" type="text/css" href="styles.css">
</head>
<body>
    <h2>Login Required</h2>
    <p>Please log in to access this wiki.</p>
    <?php if (!empty($error)): ?>
        <div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
        <label>Username: <input type="text" name="username" required maxlength="30" pattern="[a-zA-Z0-9_\-]{3,30}" autocomplete="username" autofocus></label><br>
        <label>Password: <input type="password" name="password" required autocomplete="current-password"></label><br>
        <button type="submit" name="login">Login</button>
    </form>
</body>
</html>
    <?php
    exit;
}

// --- User is logged in - process wiki operations ---

// Determine current page with length validation
$page = $_GET['page'] ?? $defaultPage;

if (strlen($page) > MAX_PAGE_NAME_LENGTH) {
    logMessage("Page name too long: " . strlen($page) . " chars", 'WARNING', $logFile);
    $page = $defaultPage;
}

$pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $page);

if (empty($pageSafe)) {
    $pageSafe = $defaultPage;
}

// Directory traversal protection
$realBase = realpath($pagesDir);
if ($realBase === false) {
    die("Configuration error: Pages directory not accessible");
}

$filePath = "$pagesDir/$pageSafe.md";
if (file_exists($filePath)) {
    $realFilePath = realpath($filePath);
    if ($realFilePath === false || strpos($realFilePath, $realBase) !== 0) {
        logMessage("Directory traversal attempt: $filePath", 'ERROR', $logFile);
        http_response_code(403);
        die("Security error: Invalid page request");
    }
}

// --- Handle tag pages ---
if (isset($_GET['tag'])) {
    $tag = $_GET['tag'];
    
    if (strlen($tag) > MAX_TAG_LENGTH) {
        http_response_code(400);
        die("Invalid tag: too long");
    }
    
    $tag = preg_replace('/[^a-zA-Z0-9_\-]/', '', $tag);
    
    if (empty($tag)) {
        http_response_code(400);
        die("Invalid tag");
    }
    
    $results = [];
    $files = glob("$pagesDir/*.md");
    if ($files !== false) {
        foreach ($files as $file) {
            // Skip revision files
            if (strpos($file, '.md.rev.') !== false) {
                continue;
            }
            $content = file_get_contents($file);
            if ($content !== false && preg_match('/(^|\s)#' . preg_quote($tag, '/') . '(\s|$)/', $content)) {
                $results[] = basename($file, ".md");
            }
        }
    }
    
    renderPage('Tag Results', function() use ($tag, $results) {
        ?>
        <h1>Pages tagged with <span class="tag">#<?= htmlspecialchars($tag, ENT_QUOTES, 'UTF-8') ?></span></h1>
        <ul>
            <?php foreach ($results as $pageName): ?>
                <li><a href="?page=<?= urlencode($pageName) ?>"><?= htmlspecialchars($pageName, ENT_QUOTES, 'UTF-8') ?></a></li>
            <?php endforeach; ?>
            <?php if (empty($results)): ?>
                <li>No pages found.</li>
            <?php endif; ?>
        </ul>
        <?php
    }, $nonce);
    exit;
}

// --- Handle AllTags page ---
if ($pageSafe === 'AllTags') {
    $allTags = getAllTags($pagesDir);
    
    renderPage('All Tags', function() use ($allTags) {
        ?>
        <h1>All Tags</h1>
        <p>Click a tag to see all pages using it.</p>
        <div>
            <?php foreach ($allTags as $tag): ?>
                <a href="?tag=<?= urlencode($tag) ?>" class="tag tag-link">#<?= htmlspecialchars($tag, ENT_QUOTES, 'UTF-8') ?></a>
            <?php endforeach; ?>
            <?php if (empty($allTags)): ?>
                <p>No tags found.</p>
            <?php endif; ?>
        </div>
        <?php
    }, $nonce);
    exit;
}

// --- Handle cache clearing ---
if (isset($_GET['action']) && $_GET['action'] === 'clearcache') {
    if (!validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage("CSRF token mismatch on cache clear", 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }
    
    clearAllPageCaches();
    $username = $_SESSION['user'] ?? 'unknown';
    logMessage("Cache cleared by user: $username", 'INFO', $logFile);
    
    header("Location: index.php?page=AllPages&cleared=1");
    exit;
}

// --- Handle AllPages with pagination ---
if ($pageSafe === 'AllPages') {
    $allPages = getAllPageNames($pagesDir);
    sort($allPages, SORT_NATURAL | SORT_FLAG_CASE);
    
    $totalPages = count($allPages);
    $pageNum = isset($_GET['pagenum']) ? max(1, (int)$_GET['pagenum']) : 1;
    $offset = ($pageNum - 1) * PAGES_PER_PAGE;
    $paginatedPages = array_slice($allPages, $offset, PAGES_PER_PAGE);
    $totalPageCount = ceil($totalPages / PAGES_PER_PAGE);
    
    renderPage('All Pages', function() use ($paginatedPages, $pageNum, $totalPageCount, $totalPages) {
        ?>
        <h1>All Pages</h1>
        
        <?php if (isset($_GET['cleared'])): ?>
            <div style="padding: 10px; background-color: #d4edda; color: #155724; border-radius: 4px; margin-bottom: 1em;">
                ✓ Cache cleared! Auto-links will be rebuilt when you view pages.
            </div>
        <?php endif; ?>
        
        <p>Showing <?= count($paginatedPages) ?> of <?= $totalPages ?> pages</p>
        
        <form method="post" action="?action=clearcache" style="margin-bottom: 1em;">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
            <button type="submit" style="background-color: #6c757d;">🔄 Rebuild All Links</button>
            <small style="color: #666; margin-left: 0.5em;">Use this if auto-links aren't working after creating new pages</small>
        </form>
        
        <ul>
            <?php foreach ($paginatedPages as $p): ?>
                <li><a href="?page=<?= urlencode($p) ?>"><?= htmlspecialchars($p, ENT_QUOTES, 'UTF-8') ?></a></li>
            <?php endforeach; ?>
        </ul>
        
        <?php if ($totalPageCount > 1): ?>
            <div class="pagination">
                <?php if ($pageNum > 1): ?>
                    <a href="?page=AllPages&pagenum=<?= $pageNum - 1 ?>" class="pagination-link">← Previous</a>
                <?php endif; ?>
                
                <span class="pagination-info">Page <?= $pageNum ?> of <?= $totalPageCount ?></span>
                
                <?php if ($pageNum < $totalPageCount): ?>
                    <a href="?page=AllPages&pagenum=<?= $pageNum + 1 ?>" class="pagination-link">Next →</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        <?php
    }, $nonce);
    exit;
}

// --- Handle revision history ---
if (isset($_GET['history'])) {
    $pageName = $_GET['page'] ?? $defaultPage;
    
    if (strlen($pageName) > MAX_PAGE_NAME_LENGTH) {
        http_response_code(400);
        die("Invalid page name");
    }
    
    $pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $pageName);
    if (empty($pageSafe)) {
        $pageSafe = $defaultPage;
    }
    
    $revisions = getRevisions($pageSafe);
    
    renderPage('History: ' . $pageSafe, function() use ($pageSafe, $revisions) {
        ?>
        <h1>Revision History: <?= htmlspecialchars($pageSafe, ENT_QUOTES, 'UTF-8') ?></h1>
        <p><a href="?page=<?= urlencode($pageSafe) ?>">← Back to page</a></p>
        
        <?php if (empty($revisions)): ?>
            <p>No revision history available for this page.</p>
        <?php else: ?>
            <table class="revisions-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Editor</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($revisions as $i => $rev): ?>
                        <tr>
                            <td><?= htmlspecialchars($rev['date'], ENT_QUOTES, 'UTF-8') ?><br>
                                <small style="color: #666;"><?= htmlspecialchars(formatTimeAgo($rev['timestamp']), ENT_QUOTES, 'UTF-8') ?></small>
                            </td>
                            <td><?= htmlspecialchars($rev['user'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td>
                                <a href="?page=<?= urlencode($pageSafe) ?>&viewrev=<?= $rev['timestamp'] ?>">View</a>
                                <?php if ($i < count($revisions) - 1): ?>
                                    | <a href="?page=<?= urlencode($pageSafe) ?>&diff=<?= $rev['timestamp'] ?>&oldrev=<?= $revisions[$i + 1]['timestamp'] ?>">Diff</a>
                                <?php endif; ?>
                                | 
                              
<form method="post"
      action="index.php?page=<?= urlencode($pageSafe) ?>"   
      style="display: inline;"
      onsubmit="return confirm('Restore this version? Current content will be saved as a revision.');">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
    <input type="hidden" name="restore_revision" value="<?= $rev['timestamp'] ?>">
    <input type="hidden" name="page" value="<?= htmlspecialchars($pageSafe, ENT_QUOTES, 'UTF-8') ?>">
    <button type="submit" style="background: none; border: none; color: #0066cc; text-decoration: underline; cursor: pointer; padding: 0; font-size: inherit;">Restore</button>
</form>
                                   
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        <?php
    }, $nonce);
    exit;
}

// --- Handle view revision ---
if (isset($_GET['viewrev'])) {
    $pageName = $_GET['page'] ?? $defaultPage;
    $timestamp = (int)$_GET['viewrev'];
    
    if (strlen($pageName) > MAX_PAGE_NAME_LENGTH) {
        http_response_code(400);
        die("Invalid page name");
    }
    
    $pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $pageName);
    $revisionContent = getRevisionContent($pageSafe, $timestamp);
    
    if ($revisionContent === null) {
        http_response_code(404);
        die("Revision not found");
    }
    
    $metadata = getRevisionMetadata($pageSafe, $timestamp);
    
    renderPage('Revision: ' . $pageSafe, function() use ($pageSafe, $revisionContent, $metadata, $pagesDir, $enableAutoLink) {
        ?>
        <div style="background-color: #fff3cd; padding: 1em; border-radius: 4px; margin-bottom: 1em;">
            <strong>⚠️ Viewing historical revision from <?= htmlspecialchars($metadata['date'], ENT_QUOTES, 'UTF-8') ?></strong><br>
            Edited by: <?= htmlspecialchars($metadata['user'], ENT_QUOTES, 'UTF-8') ?><br>
            <a href="?page=<?= urlencode($pageSafe) ?>">← View current version</a> | 
            <a href="?page=<?= urlencode($pageSafe) ?>&history=1">← Back to history</a>
        </div>
        
        <h1><?= htmlspecialchars($pageSafe, ENT_QUOTES, 'UTF-8') ?></h1>
        
        <?php
        $html = parseMarkdownWithAutoLink($revisionContent, $pagesDir, $pageSafe, $enableAutoLink);
        echo '<div>' . $html . '</div>';
        ?>
        <?php
    }, $nonce);
    exit;
}

// --- Handle diff view ---
if (isset($_GET['diff'])) {
    $pageName = $_GET['page'] ?? $defaultPage;
    $newTimestamp = (int)$_GET['diff'];
    $oldTimestamp = (int)$_GET['oldrev'];
    
    if (strlen($pageName) > MAX_PAGE_NAME_LENGTH) {
        http_response_code(400);
        die("Invalid page name");
    }
    
    $pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $pageName);
    $newContent = getRevisionContent($pageSafe, $newTimestamp);
    $oldContent = getRevisionContent($pageSafe, $oldTimestamp);
    
    if ($newContent === null || $oldContent === null) {
        http_response_code(404);
        die("Revision not found");
    }
    
    $newMetadata = getRevisionMetadata($pageSafe, $newTimestamp);
    $oldMetadata = getRevisionMetadata($pageSafe, $oldTimestamp);
    $diff = generateDiff($oldContent, $newContent);
    
    renderPage('Diff: ' . $pageSafe, function() use ($pageSafe, $oldMetadata, $newMetadata, $diff) {
        ?>
        <h1>Comparing Revisions: <?= htmlspecialchars($pageSafe, ENT_QUOTES, 'UTF-8') ?></h1>
        
        <p><a href="?page=<?= urlencode($pageSafe) ?>&history=1">← Back to history</a></p>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1em; margin-bottom: 1em;">
            <div>
                <strong>Older Version</strong><br>
                <?= htmlspecialchars($oldMetadata['date'], ENT_QUOTES, 'UTF-8') ?><br>
                By: <?= htmlspecialchars($oldMetadata['user'], ENT_QUOTES, 'UTF-8') ?>
            </div>
            <div>
                <strong>Newer Version</strong><br>
                <?= htmlspecialchars($newMetadata['date'], ENT_QUOTES, 'UTF-8') ?><br>
                By: <?= htmlspecialchars($newMetadata['user'], ENT_QUOTES, 'UTF-8') ?>
            </div>
        </div>
        
        <div class="diff-container">
            <pre class="diff-view"><?php
            foreach ($diff as $line) {
                $class = '';
                $symbol = '  ';
                if ($line['type'] === 'added') {
                    $class = 'diff-added';
                    $symbol = '+ ';
                } elseif ($line['type'] === 'removed') {
                    $class = 'diff-removed';
                    $symbol = '- ';
                }
                echo '<div class="' . $class . '">' . htmlspecialchars($symbol . $line['content'], ENT_QUOTES, 'UTF-8') . '</div>';
            }
            ?></pre>
        </div>
        <?php
    }, $nonce);
    exit;
}

// --- Handle restore revision ---
if (isset($_POST['restore_revision']) && isset($_POST['page'])) {
    if (!validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage("CSRF token mismatch on restore revision", 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }
    
    $timestamp = (int)$_POST['restore_revision'];
    $pageName = $_POST['page'];
    
    if (strlen($pageName) > MAX_PAGE_NAME_LENGTH) {
        http_response_code(400);
        die("Invalid page name");
    }
    
    $pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $pageName);
    if (empty($pageSafe)) {
        $pageSafe = $defaultPage;
    }
    
    $username = $_SESSION['user'] ?? 'unknown';
    
    if (restoreRevision($pageSafe, $timestamp, $username)) {
        logMessage("Revision restored for page: $pageSafe (timestamp: $timestamp) by user: $username", 'INFO', $logFile);
        header("Location: index.php?page=" . urlencode($pageSafe) . "&restored=1");
        exit;
    } else {
        logMessage("Failed to restore revision for page: $pageSafe (timestamp: $timestamp)", 'ERROR', $logFile);
        http_response_code(500);
        die("Failed to restore revision. Check the error log for details.");
    }
}

// --- Handle RecentChanges ---
if ($pageSafe === 'RecentChanges') {
    $recentChanges = getRecentChanges($pagesDir, 50);
    
    renderPage('Recent Changes', function() use ($recentChanges) {
        ?>
        <h1>Recent Changes</h1>
        <p>The 50 most recently edited pages:</p>
        <?php if (empty($recentChanges)): ?>
            <p>No pages have been edited yet.</p>
        <?php else: ?>
            <div class="recent-changes-container">
                <table class="recent-changes">
                    <thead>
                        <tr>
                            <th>Page</th>
                            <th>Last Modified</th>
                            <th>Editor</th>
                            <th>Time Ago</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentChanges as $change): ?>
                            <tr>
                                <td><a href="?page=<?= urlencode($change['page']) ?>"><?= htmlspecialchars($change['page'], ENT_QUOTES, 'UTF-8') ?></a></td>
                                <td><?= htmlspecialchars($change['date'], ENT_QUOTES, 'UTF-8') ?></td>
                                <td><?= htmlspecialchars($change['user'], ENT_QUOTES, 'UTF-8') ?></td>
                                <td class="time-ago"><?= htmlspecialchars(formatTimeAgo($change['timestamp']), ENT_QUOTES, 'UTF-8') ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
        <?php
    }, $nonce);
    exit;
}

function formatTimeAgo(int $timestamp): string
{
    $seconds = time() - $timestamp;
    if ($seconds < 60) return 'just now';
    if ($seconds < 3600) return floor($seconds / 60) . ' minutes ago';
    if ($seconds < 86400) return floor($seconds / 3600) . ' hours ago';
    if ($seconds < 604800) return floor($seconds / 86400) . ' days ago';
    if ($seconds < 2592000) return floor($seconds / 604800) . ' weeks ago';
    return floor($seconds / 2592000) . ' months ago';
}

// --- File handling ---
$file = "$pagesDir/$pageSafe.md";
$content = file_exists($file) ? file_get_contents($file) : '';
if ($content === false) {
    $content = '';
}

$isEditing = isset($_GET['edit']) && ($_SESSION['loggedin'] ?? false);

// --- Save edits with rate limiting ---
if ($isEditing && isset($_POST['content']) && isset($_POST['save'])) {
    if (!validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage("CSRF token mismatch on save", 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }

    $userIdentifier = 'edit_' . ($_SESSION['user'] ?? 'unknown');
    if (!checkRateLimit($userIdentifier, $rateLimitFile, 10, 60)) {
        http_response_code(429);
        die("Too many edit attempts. Please wait a moment.");
    }

    if (strlen($_POST['content']) > $config['max_content_size']) {
        http_response_code(413);
        die("Content too large (max " . round($config['max_content_size']/1024) . "KB)");
    }
    
    if (!is_dir($pagesDir)) {
        if (!mkdir($pagesDir, 0750, true) && !is_dir($pagesDir)) {
            die("Error: Failed to create pages directory");
        }
    }
    
    $newContent = $_POST['content'];
    $isNewPage = !file_exists("$pagesDir/$pageSafe.md");
    
    // Save current content as revision (if page exists and content changed)
    if (!$isNewPage) {
        $currentContent = file_get_contents("$pagesDir/$pageSafe.md");
        if ($currentContent !== false && $currentContent !== $newContent) {
            $username = $_SESSION['user'] ?? 'unknown';
            saveRevision($pageSafe, $currentContent, $username);
        }
    }
    
    // Write new content
    $result = file_put_contents("$pagesDir/$pageSafe.md", $newContent, LOCK_EX);
    
    if ($result === false) {
        logMessage("Failed to save file: $pagesDir/$pageSafe.md", 'ERROR', $logFile);
        http_response_code(500);
        die("Error: Failed to save the file.");
    }
    
    chmod("$pagesDir/$pageSafe.md", 0644);
    
    // Save metadata
    $username = $_SESSION['user'] ?? 'unknown';
    savePageMetadata("$pagesDir/$pageSafe.md", $username);
    
    // Clear cache
    clearPageCache($pageSafe);
    
    if ($isNewPage) {
        clearAllPageCaches();
        logMessage("New page created: $pageSafe - cleared all caches", 'INFO', $logFile);
    }
    
    // Rebuild search index
    touch(CACHE_DIR . '/.rebuild_index');
    
    logMessage("Page saved: $pageSafe by user: $username", 'INFO', $logFile);
    
    header("Location: index.php?page=" . urlencode($pageSafe));
    exit;
}

// --- Handle image upload with rate limiting ---
$uploadMessage = '';
if (isset($_FILES['image']['tmp_name']) && is_uploaded_file($_FILES['image']['tmp_name'])) {
    if (!validateCsrfToken($_POST['csrf'] ?? '')) {
        logMessage("CSRF token mismatch on image upload", 'WARNING', $logFile);
        http_response_code(403);
        die("Security error: Invalid request");
    }

    $userIdentifier = 'upload_' . ($_SESSION['user'] ?? 'unknown');
    if (!checkRateLimit($userIdentifier, $rateLimitFile, 10, 60)) {
        http_response_code(429);
        die("Too many upload attempts. Please wait a moment.");
    }

    $result = handleImageUpload($_FILES['image'], $uploadsDir, $config['max_upload_size']);
    
    if ($result['success']) {
        $uploadMessage = 'uploads/' . $result['filename'];
        $username = $_SESSION['user'] ?? 'unknown';
        logMessage("Image uploaded: {$result['filename']} by user: $username", 'INFO', $logFile);
        
        if (isset($_POST['upload_only'])) {
            echo '<div class="upload-success" data-markdown="![Image description](' . htmlspecialchars($uploadMessage, ENT_QUOTES, 'UTF-8') . ')"></div>';
            exit;
        }
    } else {
        $error = $result['message'];
        logMessage("Image upload failed: {$result['message']}", 'WARNING', $logFile);
    }
}

// --- Handle search with indexed search and pagination ---
$searchResults = [];
$searchSnippets = [];
$searchTotalResults = 0;
$searchPage = 1;
$searchTotalPages = 1;

if (isset($_GET['search']) && !empty($_GET['q'])) {
    $q = $_GET['q'];
    
    if (strlen($q) > MAX_SEARCH_LENGTH) {
        http_response_code(400);
        die("Search query too long");
    }
    
    $userIdentifier = 'search_' . ($_SESSION['user'] ?? 'unknown');
    if (!checkRateLimit($userIdentifier, $rateLimitFile, 20, 60)) {
        http_response_code(429);
        die("Too many search requests. Please wait a moment.");
    }
    
    $allSearchSnippets = searchWithIndex($q, $pagesDir);
    $searchTotalResults = count($allSearchSnippets);
    
    $searchPage = isset($_GET['searchpage']) ? max(1, (int)$_GET['searchpage']) : 1;
    $searchTotalPages = ceil($searchTotalResults / SEARCH_RESULTS_PER_PAGE);
    $searchPage = min($searchPage, max(1, $searchTotalPages));
    
    $offset = ($searchPage - 1) * SEARCH_RESULTS_PER_PAGE;
    $searchSnippets = array_slice($allSearchSnippets, $offset, SEARCH_RESULTS_PER_PAGE, true);
    $searchResults = array_keys($searchSnippets);
}

// --- Main page rendering ---
renderPage($page, function() use ($error, $searchResults, $searchSnippets, $searchTotalResults, $searchPage, $searchTotalPages, $isEditing, $content, $page, $pageSafe, $pagesDir, $enableAutoLink, $uploadMessage, $nonce) {
    if (!empty($error)): ?>
        <div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif;

    if (!empty($searchResults)): ?>
    <h2>Search Results for "<?= htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') ?>"</h2>
    
    <p>
        Found <?= $searchTotalResults ?> result<?= $searchTotalResults !== 1 ? 's' : '' ?>
        <?php if ($searchTotalPages > 1): ?>
            (showing page <?= $searchPage ?> of <?= $searchTotalPages ?>)
        <?php endif; ?>
    </p>
    
    <ul>
        <?php foreach ($searchResults as $result): ?>
            <li>
                <a href="?page=<?= urlencode($result) ?>"><?= htmlspecialchars($result, ENT_QUOTES, 'UTF-8') ?></a>
                <?php if (!empty($searchSnippets[$result])): ?>
                    <span class="snippet"><?= $searchSnippets[$result] ?></span>
                <?php endif; ?>
            </li>
        <?php endforeach; ?>
    </ul>
    
    <?php if ($searchTotalPages > 1): ?>
        <div class="pagination">
            <?php if ($searchPage > 1): ?>
                <a href="?search=1&q=<?= urlencode($_GET['q']) ?>&searchpage=<?= $searchPage - 1 ?>" class="pagination-link">← Previous</a>
            <?php endif; ?>
            
            <span class="pagination-info">Page <?= $searchPage ?> of <?= $searchTotalPages ?></span>
            
            <?php if ($searchPage < $searchTotalPages): ?>
                <a href="?search=1&q=<?= urlencode($_GET['q']) ?>&searchpage=<?= $searchPage + 1 ?>" class="pagination-link">Next →</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    
    <?php elseif ($isEditing): ?>
        <h2>Editing: <?= htmlspecialchars($page, ENT_QUOTES, 'UTF-8') ?></h2>
        <form method="post" enctype="multipart/form-data" id="editForm">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8') ?>">
            <div id="toolbar">
                <button type="button" id="btn-bold"><b>B</b></button>
                <button type="button" id="btn-italic"><i>I</i></button>
                <button type="button" id="btn-link">Link</button>
                <label for="image-upload" style="cursor: pointer; padding: 0.4em 0.8em; border: 1px solid #888; border-radius: 4px; background-color: #f0f0f0; display: inline-block; margin-right: 0.3em;">
                    📷 Image
                </label>
                <input type="file" id="image-upload" name="image" accept="image/*" style="display: none;">
                <button type="button" id="btn-help" title="Image alignment help">❓</button>
            </div>
            <textarea id="editbox" name="content" autofocus><?= htmlspecialchars($content, ENT_QUOTES, 'UTF-8') ?></textarea>
            <button type="submit" name="save">Save</button>
            <a href="?page=<?= urlencode($page) ?>"><button type="button">Cancel</button></a>
        </form>
    <?php else: ?>
        <?php if (isset($_GET['restored'])): ?>
            <div style="padding: 10px; background-color: #d4edda; color: #155724; border-radius: 4px; margin-bottom: 1em;">
                ✓ Previous revision restored successfully!
            </div>
        <?php endif; ?>
        
        <h1><?= htmlspecialchars($page, ENT_QUOTES, 'UTF-8') ?></h1>
        <?php
        $cachedHtml = getCachedHtml($page, $content);
        
        if ($cachedHtml !== null) {
            echo '<div>' . $cachedHtml . '</div>';
        } else {
            $html = parseMarkdownWithAutoLink($content, $pagesDir, $page, $enableAutoLink);
            echo '<div>' . $html . '</div>';
            setCachedHtml($page, $content, $html);
        }
        ?>
        
        <div style="clear: both;"></div>
        
        <?php if ($_SESSION['loggedin'] ?? false): ?>
            <p>
                <a href="?page=<?= urlencode($page) ?>&edit=1">Edit this page</a>
                <?php if (!empty($content)): ?>
                    | <a href="?page=<?= urlencode($page) ?>&history=1">📜 View history</a>
                <?php endif; ?>
            </p>
        <?php endif; ?>
       
        <?php
        if (!empty($content)) {
            $backlinks = getBacklinks($page, $pagesDir);
            $relatedPages = getRelatedPagesByTags($page, $content, $pagesDir);
            
            if (!empty($backlinks) || !empty($relatedPages)): ?>
                <hr>
                
                <?php if (!empty($backlinks)): ?>
                    <h3>Pages that link here</h3>
                    <ul>
                        <?php foreach ($backlinks as $backlink): ?>
                            <li><a href="?page=<?= urlencode($backlink) ?>" class="int"><?= htmlspecialchars($backlink, ENT_QUOTES, 'UTF-8') ?></a></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
                
                <?php if (!empty($relatedPages)): ?>
                    <h3>Related pages</h3>
                    <ul>
                        <?php foreach ($relatedPages as $pageName => $info): ?>
                            <li>
                                <a href="?page=<?= urlencode($pageName) ?>" class="int"><?= htmlspecialchars($pageName, ENT_QUOTES, 'UTF-8') ?></a>
                                <small class="tag-match">
                                    (<?= $info['count'] ?> shared tag<?= $info['count'] > 1 ? 's' : '' ?>: 
                                    <?php
                                    $displayTags = array_slice($info['tags'], 0, 3);
                                    $tagLinks = [];
                                    foreach ($displayTags as $tag) {
                                        $tagLinks[] = '<a href="?tag=' . urlencode($tag) . '" class="tag">#' . htmlspecialchars($tag, ENT_QUOTES, 'UTF-8') . '</a>';
                                    }
                                    echo implode(', ', $tagLinks);
                                    if (count($info['tags']) > 3) {
                                        echo ', ...';
                                    }
                                    ?>)
                                </small>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif;
        }
        ?>
    <?php endif;
}, $nonce);
