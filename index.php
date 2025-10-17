<?php
declare(strict_types=1);

// Protection layer (works on Apache and Nginx)
require_once __DIR__ . '/protect.php';

// Include functions
require_once __DIR__ . '/functions.php';

// --- Determine if connection is secure (support proxies using X-Forwarded-Proto) ---
$isSecure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
    (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');

// --- Security Headers ---
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
// Add HSTS when served over HTTPS (including behind proxies that set X-Forwarded-Proto)
if ($isSecure) {
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
}

// --- Configuration ---
$pagesDir = __DIR__ . '/pages';
$uploadsDir = __DIR__ . '/uploads';
$defaultPage = 'Home';
$usersFile = __DIR__ . '/users.json';
$enableAutoLink = true;

// Ensure directories exist with proper permissions
if (!is_dir($pagesDir)) {
    mkdir($pagesDir, 0750, true);
}

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0755, true);
}

// Create index.php in protected directories to block directory listing
foreach ([$pagesDir, $uploadsDir] as $dir) {
    $indexFile = $dir . '/index.php';
    if (!file_exists($indexFile)) {
        file_put_contents($indexFile, '<?php http_response_code(403); die("Access denied"); ?>');
        chmod($indexFile, 0644);
    }
}

// --- Session Security ---
ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');

// Use secure flag detection that accounts for reverse proxies
$cookieSecure = $isSecure;

// Automatically detect directory for session path isolation
$scriptPath = dirname($_SERVER['SCRIPT_NAME']);
if ($scriptPath === '/') {
    $scriptPath = '/';
} else {
    $scriptPath = rtrim($scriptPath, '/') . '/';
}

session_set_cookie_params([
    'lifetime' => 3600,
    'path' => $scriptPath,
    'secure' => $cookieSecure,
    'httponly' => true,
    'samesite' => 'Strict'
]);

// Use separate session save path for each wiki instance
$sessionPath = __DIR__ . '/sessions';
if (!is_dir($sessionPath)) {
    mkdir($sessionPath, 0700, true);
}
session_save_path($sessionPath);

session_start();

// Helper to terminate a session cleanly and remove the session cookie
function endSession(): void
{
    // Unset all session variables
    $_SESSION = [];

    // If cookies are used, delete the session cookie
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        // Use array options for setcookie where available
        $cookieOpts = [
            'expires' => time() - 42000,
            'path' => $params['path'] ?? '/',
            'domain' => $params['domain'] ?? '',
            'secure' => $params['secure'] ?? false,
            'httponly' => $params['httponly'] ?? true,
        ];
        if (PHP_VERSION_ID >= 70300) {
            // Preserve samesite when supported
            $cookieOpts['samesite'] = $params['samesite'] ?? 'Strict';
            setcookie(session_name(), '', $cookieOpts);
        } else {
            setcookie(session_name(), '', $cookieOpts['expires'], $cookieOpts['path'] . '; samesite=Strict', $cookieOpts['domain'], $cookieOpts['secure'], $cookieOpts['httponly']);
        }
    }

    // Destroy server-side session data
    session_destroy();
}

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['init'])) {
    session_regenerate_id(true);
    $_SESSION['init'] = true;
    $_SESSION['created'] = time();
}

// Session timeout (1 hour)
if (isset($_SESSION['created']) && (time() - $_SESSION['created'] > 3600)) {
    endSession();
    session_start();
}

// Load users
$users = file_exists($usersFile) ? json_decode(file_get_contents($usersFile), true) : [];
if (!is_array($users)) {
    $users = [];
}

// --- CSRF Token Generation ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Rate limiting for login ---
if (!isset($_SESSION['failed_attempts'])) {
    $_SESSION['failed_attempts'] = 0;
    $_SESSION['last_attempt'] = 0;
}

// --- Handle login ---
$error = '';
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(400);
        die("Security error: Invalid request");
    }

    $timeSinceLastAttempt = time() - $_SESSION['last_attempt'];
    if ($_SESSION['failed_attempts'] >= 5 && $timeSinceLastAttempt < 300) {
        http_response_code(429);
        die("Too many failed login attempts. Please try again in 5 minutes.");
    }

    $_SESSION['last_attempt'] = time();
    
    $username = $_POST['username'];
    if (!preg_match('/^[a-zA-Z0-9_\-]{3,30}$/', $username)) {
        $error = "Invalid username format.";
    } else {
        if (isset($users[$username]) && password_verify($_POST['password'], $users[$username])) {
            session_regenerate_id(true);
            $_SESSION['loggedin'] = true;
            $_SESSION['user'] = $username;
            $_SESSION['failed_attempts'] = 0;
            $_SESSION['last_activity'] = time();
            header("Location: index.php");
            exit;
        } else {
            $_SESSION['failed_attempts']++;
            $error = "Incorrect username or password.";
            sleep(2);
        }
    }
}

// --- Handle logout ---
if (isset($_GET['logout'])) {
    endSession();
    header("Location: index.php");
    exit;
}

// --- Activity timeout check ---
if (isset($_SESSION['loggedin']) && isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > 1800) {
        endSession();
        header("Location: index.php");
        exit;
    }
    $_SESSION['last_activity'] = time();
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
    });
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
    });
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
    });
    exit;
}

// --- File handling ---
$file = "$pagesDir/$pageSafe.md";
$content = file_exists($file) ? file_get_contents($file) : '';
if ($content === false) {
    $content = '';
}

$isEditing = isset($_GET['edit']) && ($_SESSION['loggedin'] ?? false);

// --- Handle image upload ---
$uploadMessage = '';
if (isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(400);
        die("Security error: Invalid request");
    }
    
    $result = handleImageUpload($_FILES['image'], $uploadsDir);
    
    if ($result['success']) {
        $uploadMessage = 'uploads/' . $result['filename'];
        
        // If this is an AJAX upload (upload_only flag), return minimal HTML
        if (isset($_POST['upload_only'])) {
            echo '<div class="upload-success" data-markdown="![Image description](' . htmlspecialchars($uploadMessage, ENT_QUOTES, 'UTF-8') . ')"></div>';
            exit;
        }
    } else {
        $error = $result['message'];
    }
}

// --- Save edits ---
if ($isEditing && isset($_POST['content']) && !isset($_POST['upload_only'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(400);
        die("Security error: Invalid request");
    }
    
    if (strlen($_POST['content']) > 1048576) {
        http_response_code(413);
        die("Content too large");
    }
    
    if (!is_dir($pagesDir)) {
        mkdir($pagesDir, 0750, true);
    }
    
    $newContent = $_POST['content'];
    $result = file_put_contents("$pagesDir/$pageSafe.md", $newContent, LOCK_EX);
    
    if ($result === false) {
        http_response_code(500);
        die("Error: Failed to save the file.");
    }
    
    chmod("$pagesDir/$pageSafe.md", 0644);
    
    header("Location: index.php?page=" . urlencode($pageSafe));
    exit;
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
renderPage($page, function() use ($error, $searchResults, $searchSnippets, $isEditing, $content, $page, $pageSafe, $pagesDir, $enableAutoLink, $uploadMessage) {
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
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div id="toolbar">
                <button type="button" onclick="formatText('**', '**')"><b>B</b></button>
                <button type="button" onclick="formatText('*', '*')"><i>I</i></button>
                <button type="button" onclick="insertLink()">Link</button>
                <label for="image-upload" style="cursor: pointer; padding: 0.4em 0.8em; border: 1px solid #888; border-radius: 4px; background-color: #f0f0f0; display: inline-block; margin-right:[...]">
                    📷 Image
                </label>
                <input type="file" id="image-upload" name="image" accept="image/*" style="display: none;" onchange="uploadImage()">
                <button type="button" onclick="showImageHelp()" title="Image alignment help">❓</button>

            </div>
            <textarea id="editbox" name="content" autofocus><?= htmlspecialchars($content, ENT_QUOTES, 'UTF-8') ?></textarea>
            <button type="submit" name="save">Save</button>
            <a href="?page=<?= urlencode($page) ?>"><button type="button">Cancel</button></a>
        </form>
        <script>
            function uploadImage() {
                // Show uploading message
                const toolbar = document.getElementById('toolbar');
                const uploadStatus = document.createElement('span');
                uploadStatus.id = 'upload-status';
                uploadStatus.style.marginLeft = '1em';
                uploadStatus.style.color = '#0066cc';
                uploadStatus.textContent = '⏳ Uploading...';
                toolbar.appendChild(uploadStatus);
                
                // Create FormData with image and CSRF token
                const formData = new FormData();
                const imageFile = document.getElementById('image-upload').files[0];
                formData.append('image', imageFile);
                formData.append('csrf_token', document.querySelector('input[name="csrf_token"]').value);
                formData.append('upload_only', '1');
                
                // Upload via AJAX
                fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.text())
                .then(html => {
                    // Parse response to get upload message
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const uploadDiv = doc.querySelector('.upload-success');
                    
                    if (uploadDiv) {
                        const markdownCode = uploadDiv.getAttribute('data-markdown');
                        
                        // Insert at cursor position
                        const textarea = document.getElementById('editbox');
                        const start = textarea.selectionStart;
                        const end = textarea.selectionEnd;
                        const before = textarea.value.substring(0, start);
                        const after = textarea.value.substring(end);
                        textarea.value = before + markdownCode + after;
                        
                        // Update cursor position
                        const newPos = start + markdownCode.length;
                        textarea.selectionStart = newPos;
                        textarea.selectionEnd = newPos;
                        textarea.focus();
                        
                        // Show success message
                        uploadStatus.textContent = '✓ Image inserted!';
                        uploadStatus.style.color = '#28a745';
                        setTimeout(() => uploadStatus.remove(), 3000);
                    } else {
                        // Show error
                        uploadStatus.textContent = '✗ Upload failed';
                        uploadStatus.style.color = '#dc3545';
                    }
                    
                    // Reset file input
                    document.getElementById('image-upload').value = '';
                })
                .catch(error => {
                    uploadStatus.textContent = '✗ Upload error';
                    uploadStatus.style.color = '#dc3545';
                    console.error('Upload error:', error);
                });
            }
            
            function formatText(startTag, endTag) {
                const textarea = document.getElementById("editbox");
                const start = textarea.selectionStart;
                const end = textarea.selectionEnd;
                const selected = textarea.value.substring(start, end);
                const before = textarea.value.substring(0, start);
                const after = textarea.value.substring(end);
                textarea.value = before + startTag + selected + endTag + after;
                textarea.focus();
                if (start === end) {
                    textarea.selectionStart = textarea.selectionEnd = start + startTag.length;
                } else {
                    textarea.selectionStart = start;
                    textarea.selectionEnd = end + startTag.length + endTag.length;
                }
            }

            function insertLink() {
                const url = prompt("Enter the page name or URL for the link:");
                if (!url) return;
                const textarea = document.getElementById("editbox");
                const start = textarea.selectionStart;
                const end = textarea.selectionEnd;
                const selected = textarea.value.substring(start, end) || url;
                const before = textarea.value.substring(0, start);
                const after = textarea.value.substring(end);
                let formatted;
                if (url.match(/^(http|https):\/\//i)) {
                    formatted = `[${selected}](${url})`;
                } else {
                    formatted = `[[${selected}]]`;
                }
                textarea.value = before + formatted + after;
                textarea.focus();
                textarea.selectionStart = textarea.selectionEnd = start + formatted.length;
            }
     
     function showImageHelp() {
        alert('Image Alignment:\n\n' +
              '![alt](url){.center} - Center image\n' +
              '![alt](url){.left} - Float left\n' +
              '![alt](url){.right} - Float right\n\n' +
              'Image Sizes:\n\n' +
              '{.small} - 300px max\n' +
              '{.medium} - 600px max\n' +
              '{.large} - 900px max\n' +
              '{.full} - Full width\n\n' +
              'Combine them:\n' +
              '![alt](url){.left .small}');
    }

        </script>
    <?php else: ?>
        <h1><?= htmlspecialchars($page, ENT_QUOTES, 'UTF-8') ?></h1>
        <div><?= parseMarkdownWithAutoLink($content, $pagesDir, $page, $enableAutoLink) ?></div>
        
        <?php if ($_SESSION['loggedin'] ?? false): ?>
            <p><a href="?page=<?= urlencode($page) ?>&edit=1">Edit this page</a></p>
        <?php endif; ?>
        
        <?php
        // Display backlinks and related pages
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

    if (!($_SESSION['loggedin'] ?? false)): ?>
        <hr>
        <h3>Login</h3>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <label>Username: <input type="text" name="username" required maxlength="30" pattern="[a-zA-Z0-9_\-]{3,30}"></label><br>
            <label>Password: <input type="password" name="password" required></label><br>
            <button type="submit" name="login">Login</button>
        </form>
    <?php endif;
});
?>