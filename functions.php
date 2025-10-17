<?php
declare(strict_types=1);

/**
 * Parse markdown text to HTML
 * @param string $text Raw markdown content
 * @return string HTML output
 */
function parseMarkdown(string $text): string
{
    $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    
    // Code blocks
    $text = preg_replace_callback('/``````/s', function ($m) {
        return '<pre><code>' . $m[1] . '</code></pre>';
    }, $text);
    
    // Inline code
    $text = preg_replace_callback('/`([^`]+)`/', function($m) {
        return '<code>' . $m[1] . '</code>';
    }, $text);
    
  // Images with URL validation and optional alignment/sizing classes
// Supports: ![alt](url){.center}, ![alt](url){.left .small}, etc.
$text = preg_replace_callback('/!\[([^\]]*)\]\(([^)]+)\)(?:\{([^}]+)\})?/', function($m) {
    $alt = $m[1];
    $url = $m[2];
    $modifiers = isset($m[3]) ? trim($m[3]) : '';
    
    // Parse modifiers (e.g., .center .small)
    $classes = [];
    if (!empty($modifiers)) {
        preg_match_all('/\.(\w+)/', $modifiers, $matches);
        foreach ($matches[1] as $class) {
            $classes[] = 'img-' . $class;
        }
    }
    
    $classAttr = !empty($classes) ? ' class="' . implode(' ', $classes) . '"' : '';
    $style = 'style="max-width:100%; max-height:400px;"';
    
    if (preg_match('/^https?:\/\//i', $url)) {
        return '<img src="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" alt="' . htmlspecialchars($alt, ENT_QUOTES, 'UTF-8') . '"' . $classAttr . ' ' . $style . '>';
    }
    // Support local images in uploads directory
    if (preg_match('/^uploads\//i', $url)) {
        return '<img src="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" alt="' . htmlspecialchars($alt, ENT_QUOTES, 'UTF-8') . '"' . $classAttr . ' ' . $style . '>';
    }
    return htmlspecialchars($m[0], ENT_QUOTES, 'UTF-8');
}, $text);

    
    // Headings
    $text = preg_replace('/^###### (.*)$/m', '<h6>$1</h6>', $text);
    $text = preg_replace('/^##### (.*)$/m', '<h5>$1</h5>', $text);
    $text = preg_replace('/^#### (.*)$/m', '<h4>$1</h4>', $text);
    $text = preg_replace('/^### (.*)$/m', '<h3>$1</h3>', $text);
    $text = preg_replace('/^## (.*)$/m', '<h2>$1</h2>', $text);
    $text = preg_replace('/^# (.*)$/m', '<h1>$1</h1>', $text);
    
    // Lists
    $text = preg_replace('/^\s*[\-\*]\s+(.*)$/m', '<li>$1</li>', $text);
    $text = preg_replace('/(<li>.*?<\/li>\s*)+/s', '<ul>$0</ul>', $text);
    
    // Bold and italic
    $text = preg_replace('/\*\*\*(.+?)\*\*\*/', '<strong><em>$1</em></strong>', $text);
    $text = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $text);
    $text = preg_replace('/\*(.+?)\*/', '<em>$1</em>', $text);
    
    // External links with validation
    $text = preg_replace_callback('/\[([^\]]+)\]\(([^)]+)\)/', function($m) {
        $linkText = $m[1];
        $url = $m[2];
        if (preg_match('/^https?:\/\//i', $url)) {
            return '<a href="' . $url . '" class="ext" target="_blank" rel="noopener noreferrer">' . $linkText . '</a>';
        }
        return $m[0];
    }, $text);
    
    // Internal links
    $text = preg_replace_callback('/\[\[([^\]]+)\]\]/', function($m) {
        $page = trim($m[1]);
        $url = '?page=' . urlencode($page);
        return '<a href="' . $url . '" class="int">' . $page . '</a>';
    }, $text);
    
    // Tags
    $text = preg_replace_callback('/(^|\s)#([a-zA-Z0-9_\-]+)/', function($m) {
        return $m[1] . '<a href="?tag=' . urlencode($m[2]) . '" class="tag">#' . $m[2] . '</a>';
    }, $text);
    
    // Line breaks
    $lines = explode("\n", $text);
    foreach ($lines as &$line) {
        if (!preg_match('/^\s*<(h\d|ul|ol|li|pre|code|blockquote|p|table|tr|td|th)[ >]/', $line) && !empty(trim($line))) {
            $line .= '<br>';
        }
    }
    
    return implode("\n", $lines);
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
 * @param string $text The text to process (before markdown parsing)
 * @param string $pagesDir Pages directory
 * @param string $currentPage Current page (to avoid self-linking)
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
        $pattern = '/(?<!\[\[)(?<!\[)\b(' . $escapedPage . ')\b(?!\]\])(?!\])/i';
        
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
 * @param string $pagesDir Pages directory for auto-linking
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
 * Find all pages that link to the current page (backlinks)
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
 * Handle image upload
 * @param array $file File from $_FILES
 * @param string $uploadsDir Directory for uploads
 * @return array Result with 'success' boolean and 'message' or 'filename'
 */
function handleImageUpload(array $file, string $uploadsDir): array
{
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'Upload error occurred'];
    }
    
    // Validate file size (max 5MB)
    if ($file['size'] > 5 * 1024 * 1024) {
        return ['success' => false, 'message' => 'File too large (max 5MB)'];
    }
    
    // Validate MIME type
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($mimeType, $allowedTypes)) {
        return ['success' => false, 'message' => 'Invalid file type. Only JPG, PNG, GIF, and WebP allowed'];
    }
    
    // Generate safe filename
    $extension = match($mimeType) {
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
        default => 'jpg'
    };
    
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

/**
 * Render navigation bar
 */
function renderNav(): void
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
 */
function renderPage(string $title, callable $contentCallback): void
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
    <?php renderNav(); ?>
    <?php $contentCallback(); ?>
</body>
</html>
    <?php
}

