<?php
declare(strict_types=1);

// Load configuration FIRST (use require, not require_once)
$config = require __DIR__ . '/config.php';

// Protection layer (works on Apache and Nginx)
require_once __DIR__ . '/protect.php';

// Include functions (this starts the session already!)
require_once __DIR__ . '/functions.php';

// Generate CSP nonce for this request
$nonce = generateNonce();

// --- Security Headers ---
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('X-XSS-Protection: 1; mode=block');

// Add these cache control headers
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Force HTTPS in production
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

// Extract config values
$pagesDir = $config['pages_dir'];
$uploadsDir = $config['uploads_dir'];
$sessionPath = $config['sessions_dir'];
$usersFile = $config['users_file'];
$rateLimitFile = $config['rate_limit_file'];
$logFile = $config['log_file'];
$defaultPage = $config['default_page'];
$enableAutoLink = $config['enable_auto_link'];

// Ensure directories exist
if (!is_dir($pagesDir)) {
    @mkdir($pagesDir, 0755, true);
    $indexFile = $pagesDir . '/Home.md';
    if (!file_exists($indexFile)) {
        file_put_contents($indexFile, "# Welcome to Simple Wiki\n\nEdit this page to get started.");
        chmod($indexFile, 0644);
    }
}

// NO SESSION START HERE - functions.php already did it!
// Session is already active from functions.php

// Regenerate session ID on first visit to prevent session fixation
if (!isset($_SESSION['init'])) {
    session_regenerate_id(true);
    $_SESSION['init'] = true;
    $_SESSION['created'] = time();
}

// Session timeout (absolute timeout)
if (isset($_SESSION['created']) && (time() - $_SESSION['created'] > $config['session_lifetime'])) {
    session_unset();
    session_destroy();
    clearSessionCookie();
    header("Location: index.php");
    exit;
}

// Load users
$users = file_exists($usersFile) ? json_decode(file_get_contents($usersFile), true) : [];
if (!is_array($users)) {
    $users = [];
}

// --- Handle login with IP-based rate limiting ---
$error = '';
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    // Simple CSRF check
    if (!isset($_POST['csrf']) || $_POST['csrf'] !== ($_SESSION['csrf_token'] ?? '')) {
        logMessage('CSRF token mismatch on login', 'WARNING', $logFile);
        die("Security error: Invalid request");
    }

    $clientIp = getClientIp();
    
    // Check IP-based rate limit
    if (!checkRateLimit($clientIp, $rateLimitFile, $config['max_login_attempts'], $config['login_block_duration'])) {
        logMessage("Rate limit exceeded for IP: $clientIp", 'WARNING', $logFile);
        die("Too many failed login attempts. Please try again in " . ($config['login_block_duration'] / 60) . " minutes.");
    }
    
    $username = $_POST['username'];
    if (!preg_match('/^[a-zA-Z0-9_\-]{3,30}$/', $username)) {
        $error = "Invalid username format.";
        logMessage("Invalid username format attempted: $username from IP: $clientIp", 'WARNING', $logFile);
    } else {
        if (isset($users[$username]) && password_verify($_POST['password'], $users[$username])) {
            session_regenerate_id(true);
            $_SESSION['loggedin'] = true;
            $_SESSION['user'] = $username;
            $_SESSION['last_activity'] = time();
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

// --- Handle logout with proper cookie clearing ---
// FIX #1: Now handles both GET and POST logout requests
if (isset($_GET['logout']) || isset($_POST['logout'])) {
    $username = $_SESSION['user'] ?? 'unknown';
    $clientIp = getClientIp();
    logMessage("User logout: $username from IP: $clientIp", 'INFO', $logFile);
    
    session_unset();
    session_destroy();
    clearSessionCookie();
    
    header("Location: index.php");
    exit;
}

// --- Activity timeout check ---
if (isset($_SESSION['loggedin']) && isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > $config['session_timeout']) {
        session_unset();
        session_destroy();
        clearSessionCookie();
        header("Location: index.php");
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// Simple login requirement
// FIX #2: Removed nested condition - always show login form if not authenticated
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    // User is not logged in - show login form
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

// --- Determine current page ---
$page = $_GET['page'] ?? $defaultPage;
$pageSafe = preg_replace('/[^\p{L}0-9 _\-]/u', '', $page);

if (empty($pageSafe) || strlen($pageSafe) > 100) {
    $pageSafe = $defaultPage;
}

// --- Directory traversal protection ---
$realBase = realpath($pagesDir);
if ($realBase === false) {
    die("Configuration error: Pages directory not accessible");
}

$filePath = "$pagesDir/$pageSafe.md";
$realFilePath = realpath($filePath);
if ($realFilePath !== false && strpos($realFilePath, $realBase) !== 0) {
    logMessage("Directory traversal attempt: $filePath", 'ERROR', $logFile);
    die("Security error: Invalid page request");
}

// --- Handle tag pages ---
if (isset($_GET['tag'])) {
    $tag = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['tag']);
    if (strlen($tag) > 50) {
        die("Invalid tag");
    }
    
    $results = [];
    $files = glob("$pagesDir/*.md");
    if ($files !== false) {
        foreach ($files as $file) {
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
    $allTags = [];
    $files = glob("$pagesDir/*.md");
    if ($files !== false) {
        foreach ($files as $filename) {
            $content = file_get_contents($filename);
            if ($content !== false && preg_match_all('/#([a-zA-Z0-9_\-]+)/', $content, $matches)) {
                foreach ($matches[1] as $tag) {
                    if (strlen($tag) <= 50) {
                        $allTags[$tag] = true;
                    }
                }
            }
        }
    }
    $allTags = array_keys($allTags);
    sort($allTags, SORT_NATURAL | SORT_FLAG_CASE);
    
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

// --- Handle AllPages ---
if ($pageSafe === 'AllPages') {
    $allPages = [];
    $files = glob("$pagesDir/*.md");
    if ($files !== false) {
        foreach ($files as $filename) {
            $allPages[] = basename($filename, '.md');
        }
    }
    sort($allPages, SORT_NATURAL | SORT_FLAG_CASE);
    
    renderPage('All Pages', function() use ($allPages) {
        ?>
        <h1>All Pages</h1>
        <ul>
            <?php foreach ($allPages as $p): ?>
                <li><a href="?page=<?= urlencode($p) ?>"><?= htmlspecialchars($p, ENT_QUOTES, 'UTF-8') ?></a></li>
            <?php endforeach; ?>
        </ul>
        <?php
    }, $nonce);
    exit;
}

// --- File handling ---
$file = "$pagesDir/$pageSafe.md";
$content = file_exists($file) ? file_get_contents($file) : '';
if ($content === false) {
    $content = '';
}

$isEditing = isset($_GET['edit']) && ($_SESSION['loggedin'] ?? false);

// --- Save edits FIRST (before any output/error handling) ---
if ($isEditing && isset($_POST['content']) && isset($_POST['save'])) {
    // Simple CSRF check
    if (!isset($_POST['csrf']) || $_POST['csrf'] !== ($_SESSION['csrf_token'] ?? '')) {
        logMessage("CSRF token mismatch on save", 'WARNING', $logFile);
        die("Security error: Invalid request");
    }

    if (strlen($_POST['content']) > $config['max_content_size']) {
        die("Content too large (max " . round($config['max_content_size']/1024) . "KB)");
    }
    
    if (!is_dir($pagesDir)) {
        mkdir($pagesDir, 0750, true);
    }
    
    $newContent = $_POST['content'];
    
    // Atomic write: write to temp file then rename
    $tempFile = "$pagesDir/$pageSafe.md.tmp";
    $result = file_put_contents($tempFile, $newContent, LOCK_EX);
    
    if ($result === false) {
        logMessage("Failed to write temp file: $tempFile", 'ERROR', $logFile);
        die("Error: Failed to save the file.");
    }
    
    chmod($tempFile, 0644);
    
    if (!rename($tempFile, "$pagesDir/$pageSafe.md")) {
        logMessage("Failed to rename temp file to: $pagesDir/$pageSafe.md", 'ERROR', $logFile);
        die("Error: Failed to save the file.");
    }
    
    $username = $_SESSION['user'] ?? 'unknown';
    logMessage("Page saved: $pageSafe by user: $username", 'INFO', $logFile);
    
    header("Location: index.php?page=" . urlencode($pageSafe));
    exit;
}

// --- Handle image upload ---
$uploadMessage = '';
if (isset($_FILES['image']['tmp_name']) && is_uploaded_file($_FILES['image']['tmp_name'])) {
    // Simple CSRF check
    if (!isset($_POST['csrf']) || $_POST['csrf'] !== ($_SESSION['csrf_token'] ?? '')) {
        logMessage("CSRF token mismatch on image upload", 'WARNING', $logFile);
        die("Security error: Invalid request");
    }

    $result = handleImageUpload(
        $_FILES['image'], 
        $uploadsDir, 
        $config['max_upload_size']
    );
    
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

// --- Handle search ---
$searchResults = [];
$searchSnippets = [];
if (isset($_GET['search']) && !empty($_GET['q'])) {
    $q = $_GET['q'];
    if (strlen($q) > 100) {
        die("Search query too long");
    }
    
    $qLower = strtolower($q);
    $files = glob("$pagesDir/*.md");
    if ($files !== false) {
        foreach ($files as $filename) {
            $basename = basename($filename, '.md');
            $contents = file_get_contents($filename);
            if ($contents === false) {
                continue;
            }
            
            if (stripos($contents, $qLower) !== false || stripos($basename, $qLower) !== false) {
                $searchResults[] = $basename;
                $snippet = '';
                if (stripos($contents, $qLower) !== false) {
                    $matchPos = stripos($contents, $qLower);
                    $start = max(0, $matchPos - 60);
                    $length = min(120, strlen($contents) - $start);
                    $snippetRaw = substr($contents, $start, $length);
                    $snippet = preg_replace(
                        '/(' . preg_quote($q, '/') . ')/i',
                        '<mark>$1</mark>',
                        htmlspecialchars($snippetRaw, ENT_QUOTES, 'UTF-8')
                    );
                } elseif (stripos($basename, $qLower) !== false) {
                    $snippet = '<mark>' . htmlspecialchars($basename, ENT_QUOTES, 'UTF-8') . '</mark> (name match)';
                }
                $searchSnippets[$basename] = $snippet;
            }
        }
    }
}

// --- Main page rendering ---
renderPage($page, function() use ($error, $searchResults, $searchSnippets, $isEditing, $content, $page, $pageSafe, $pagesDir, $enableAutoLink, $uploadMessage, $nonce) {
    if (!empty($error)): ?>
        <div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif;

    if (!empty($searchResults)): ?>
        <h2>Search Results for "<?= htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') ?>"</h2>
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
        <h1><?= htmlspecialchars($page, ENT_QUOTES, 'UTF-8') ?></h1>
        <div><?= parseMarkdownWithAutoLink($content, $pagesDir, $page, $enableAutoLink) ?></div>
        
        <div style="clear: both;"></div>
        
        <?php if ($_SESSION['loggedin'] ?? false): ?>
            <p><a href="?page=<?= urlencode($page) ?>&edit=1">Edit this page</a></p>
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
?>
