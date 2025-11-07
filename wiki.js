// wiki.js - External JavaScript file for the wiki with improved auto-save

// Auto-save configuration
const AUTO_SAVE_DELAY = 5000; // 5 seconds (increased from 2)
const AUTO_SAVE_MIN_CHANGES = 10; // Minimum characters changed before saving

// Auto-save state
let autoSaveTimer = null;
let lastSavedContent = '';
let lastCheckedContent = '';
let saveInProgress = false;

// Test localStorage availability immediately
try {
    const test = 'test';
    localStorage.setItem('test', test);
    localStorage.removeItem('test');
    console.log('localStorage is available');
} catch (e) {
    console.error('localStorage is NOT available:', e);
}

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Wiki.js loaded');
    
    // Attach event listeners to toolbar buttons
    const btnBold = document.getElementById('btn-bold');
    const btnItalic = document.getElementById('btn-italic');
    const btnLink = document.getElementById('btn-link');
    const btnHelp = document.getElementById('btn-help');
    const imageUpload = document.getElementById('image-upload');
    const editbox = document.getElementById('editbox');
    
    if (btnBold) {
        btnBold.addEventListener('click', function() {
            formatText('**', '**');
        });
    }
    
    if (btnItalic) {
        btnItalic.addEventListener('click', function() {
            formatText('*', '*');
        });
    }
    
    if (btnLink) {
        btnLink.addEventListener('click', function() {
            insertLink();
        });
    }
    
    if (btnHelp) {
        btnHelp.addEventListener('click', function() {
            showImageHelp();
        });
    }
    
    if (imageUpload) {
        imageUpload.addEventListener('change', function() {
            uploadImage();
        });
    }
    
    // Initialize auto-save if we're in edit mode
    if (editbox) {
        console.log('Edit box found, initializing auto-save');
        initAutoSave();
    } else {
        console.log('No edit box found');
    }
});

// Initialize auto-save functionality
function initAutoSave() {
    const editbox = document.getElementById('editbox');
    if (!editbox) {
        console.log('Cannot initialize auto-save: editbox not found');
        return;
    }
    
    console.log('Auto-save initialized with ' + (AUTO_SAVE_DELAY / 1000) + 's delay');
    
    // Store initial content
    lastSavedContent = editbox.value;
    lastCheckedContent = editbox.value;
    
    // Load any draft from localStorage
    const pageName = getPageName();
    const draftKey = 'wiki_draft_' + pageName;
    
    console.log('Checking for draft with key:', draftKey);
    
    try {
        const savedDraft = localStorage.getItem(draftKey);
        const draftTimestamp = localStorage.getItem(draftKey + '_time');
        
        console.log('Saved draft:', savedDraft ? 'Found' : 'Not found');
        
        if (savedDraft && savedDraft !== lastSavedContent) {
            const draftDate = draftTimestamp ? new Date(parseInt(draftTimestamp)) : null;
            const timeAgo = draftDate ? formatTimeAgo(draftDate) : 'earlier';
            
            // Check if the draft is very recent (within last 5 seconds)
            const isVeryRecent = draftDate && (Date.now() - draftDate.getTime()) < 5000;
            
            if (!isVeryRecent && confirm(`A draft was saved ${timeAgo}. Would you like to restore it?`)) {
                editbox.value = savedDraft;
                lastSavedContent = savedDraft;
                lastCheckedContent = savedDraft;
                showStatus('Draft restored', 'success');
            } else {
                // Clear the draft if user declined or if it's too recent
                localStorage.removeItem(draftKey);
                localStorage.removeItem(draftKey + '_time');
            }
        }
    } catch (e) {
        console.error('Error loading draft:', e);
    }
    
    // Add status indicator
    addStatusIndicator();
    
    // Listen for changes with improved logic
    editbox.addEventListener('input', function() {
        const currentContent = editbox.value;
        
        // Calculate change size
        const changeSize = Math.abs(currentContent.length - lastCheckedContent.length);
        
        // Clear existing timer
        if (autoSaveTimer) {
            clearTimeout(autoSaveTimer);
        }
        
        // Only show "unsaved" if there are meaningful changes
        if (currentContent !== lastSavedContent && changeSize >= AUTO_SAVE_MIN_CHANGES) {
            updateStatus('unsaved');
        }
        
        // Set new timer
        autoSaveTimer = setTimeout(function() {
            // Only save if content changed significantly
            if (currentContent !== lastSavedContent) {
                const totalChange = Math.abs(currentContent.length - lastSavedContent.length);
                
                if (totalChange >= AUTO_SAVE_MIN_CHANGES) {
                    saveDraft();
                    lastCheckedContent = currentContent;
                }
            }
        }, AUTO_SAVE_DELAY);
    });
    
    // Update the display every minute to show relative time
    setInterval(function() {
        const pageName = getPageName();
        const draftKey = 'wiki_draft_' + pageName;
        const draftTimestamp = localStorage.getItem(draftKey + '_time');
        
        if (draftTimestamp) {
            const saveTime = new Date(parseInt(draftTimestamp));
            const timeStr = saveTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            const statusDiv = document.getElementById('save-status');
            if (statusDiv && statusDiv.textContent.includes('Draft saved')) {
                statusDiv.textContent = '✓ Draft saved at ' + timeStr;
            }
        }
    }, 60000);
    
    // Save on page unload
    window.addEventListener('beforeunload', function(e) {
        const editbox = document.getElementById('editbox');
        if (editbox && editbox.value !== lastSavedContent && !saveInProgress) {
            saveDraft(true); // Synchronous save
            e.preventDefault();
            e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            return e.returnValue;
        }
    });
    
    // Intercept form submission to clear draft
    const editForm = document.getElementById('editForm');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            console.log('Form submitted, clearing draft');
            saveInProgress = true;
            const pageName = getPageName();
            const draftKey = 'wiki_draft_' + pageName;
            try {
                localStorage.removeItem(draftKey);
                localStorage.removeItem(draftKey + '_time');
            } catch (e) {
                console.error('Error clearing draft:', e);
            }
        });
    }
}

// Add status indicator to the page
function addStatusIndicator() {
    const toolbar = document.getElementById('toolbar');
    if (!toolbar) {
        console.log('Cannot add status indicator: toolbar not found');
        return;
    }
    
    // Check if already exists
    if (document.getElementById('save-status')) {
        return;
    }
    
    const statusDiv = document.createElement('div');
    statusDiv.id = 'save-status';
    statusDiv.style.cssText = 'display: inline-block; margin-left: 1em; padding: 0.4em 0.8em; border-radius: 4px; font-size: 0.9em;';
    toolbar.appendChild(statusDiv);
    
    updateStatus('saved');
}

// Update status indicator
function updateStatus(status, timestamp = null) {
    const statusDiv = document.getElementById('save-status');
    if (!statusDiv) return;
    
    const now = new Date();
    const timeStr = timestamp || now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    switch(status) {
        case 'saved':
            statusDiv.textContent = '✓ Draft saved at ' + timeStr;
            statusDiv.style.backgroundColor = '#d4edda';
            statusDiv.style.color = '#155724';
            break;
        case 'unsaved':
            statusDiv.textContent = '● Unsaved changes';
            statusDiv.style.backgroundColor = '#fff3cd';
            statusDiv.style.color = '#856404';
            break;
        case 'saving':
            statusDiv.textContent = '⟳ Saving draft...';
            statusDiv.style.backgroundColor = '#d1ecf1';
            statusDiv.style.color = '#0c5460';
            break;
        case 'error':
            statusDiv.textContent = '✗ Save failed';
            statusDiv.style.backgroundColor = '#f8d7da';
            statusDiv.style.color = '#721c24';
            break;
    }
}

// Show temporary status message
function showStatus(message, type) {
    const statusDiv = document.getElementById('save-status');
    if (!statusDiv) return;
    
    const originalContent = statusDiv.textContent;
    const originalBg = statusDiv.style.backgroundColor;
    const originalColor = statusDiv.style.color;
    
    switch(type) {
        case 'success':
            statusDiv.style.backgroundColor = '#d4edda';
            statusDiv.style.color = '#155724';
            break;
        case 'error':
            statusDiv.style.backgroundColor = '#f8d7da';
            statusDiv.style.color = '#721c24';
            break;
    }
    
    statusDiv.textContent = message;
    
    setTimeout(function() {
        statusDiv.textContent = originalContent;
        statusDiv.style.backgroundColor = originalBg;
        statusDiv.style.color = originalColor;
    }, 3000);
}

// Save draft to localStorage
function saveDraft(synchronous = false) {
    const editbox = document.getElementById('editbox');
    if (!editbox) return;
    
    const content = editbox.value;
    
    // Don't save if content hasn't changed
    if (content === lastSavedContent) {
        console.log('Content unchanged, skipping save');
        return;
    }
    
    console.log('Saving draft...');
    updateStatus('saving');
    
    try {
        const pageName = getPageName();
        const draftKey = 'wiki_draft_' + pageName;
        const now = Date.now();
        
        localStorage.setItem(draftKey, content);
        localStorage.setItem(draftKey + '_time', now.toString());
        
        lastSavedContent = content;
        
        // Show time of save
        const saveTime = new Date(now);
        const timeStr = saveTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        updateStatus('saved', timeStr);
        console.log('Draft saved successfully at', timeStr);
    } catch (e) {
        console.error('Failed to save draft:', e);
        updateStatus('error');
        
        // Check if it's a quota exceeded error
        if (e.name === 'QuotaExceededError') {
            alert('Storage quota exceeded. Please clear some old drafts or reduce content size.');
        }
    }
}

// Get current page name from URL
function getPageName() {
    const params = new URLSearchParams(window.location.search);
    const pageName = params.get('page') || 'Home';
    console.log('Current page name:', pageName);
    return pageName;
}

// Format time ago
function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
    return Math.floor(seconds / 86400) + ' days ago';
}

// Image upload function
function uploadImage() {
    const toolbar = document.getElementById('toolbar');
    let uploadStatus = document.getElementById('upload-status');
    
    if (!uploadStatus) {
        uploadStatus = document.createElement('span');
        uploadStatus.id = 'upload-status';
        uploadStatus.style.marginLeft = '1em';
        toolbar.appendChild(uploadStatus);
    }
    
    uploadStatus.style.color = '#0066cc';
    uploadStatus.textContent = 'Uploading...';
    
    const formData = new FormData();
    const imageFile = document.getElementById('image-upload').files[0];
    formData.append('image', imageFile);
    formData.append('csrf', document.querySelector('input[name="csrf"]').value);
    formData.append('upload_only', '1');
    
    fetch(window.location.href, {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(html => {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const uploadDiv = doc.querySelector('.upload-success');
        
        if (uploadDiv) {
            const markdownCode = uploadDiv.getAttribute('data-markdown');
            
            const textarea = document.getElementById('editbox');
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const before = textarea.value.substring(0, start);
            const after = textarea.value.substring(end);
            textarea.value = before + markdownCode + after;
            
            const newPos = start + markdownCode.length;
            textarea.selectionStart = newPos;
            textarea.selectionEnd = newPos;
            textarea.focus();
            
            // Trigger auto-save
            textarea.dispatchEvent(new Event('input'));
            
            uploadStatus.textContent = '✓ Image inserted!';
            uploadStatus.style.color = '#28a745';
            setTimeout(() => uploadStatus.remove(), 3000);
        } else {
            uploadStatus.textContent = '✗ Upload failed';
            uploadStatus.style.color = '#dc3545';
        }
        
        document.getElementById('image-upload').value = '';
    })
    .catch(error => {
        uploadStatus.textContent = '✗ Upload error';
        uploadStatus.style.color = '#dc3545';
        console.error('Upload error:', error);
    });
}

// Format text with markdown
function formatText(startTag, endTag) {
    const textarea = document.getElementById("editbox");
    if (!textarea) return;
    
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
    
    // Trigger auto-save
    textarea.dispatchEvent(new Event('input'));
}

// Insert link
function insertLink() {
    const url = prompt("Enter the page name or URL for the link:");
    if (!url) return;
    
    const textarea = document.getElementById("editbox");
    if (!textarea) return;
    
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
    
    // Trigger auto-save
    textarea.dispatchEvent(new Event('input'));
}

// Show image help
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

document.addEventListener('DOMContentLoaded', function() {
    const restoreForms = document.querySelectorAll('.restore-form');
    restoreForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!confirm('Restore this version? Current content will be saved as a new revision.')) {
                event.preventDefault();
            }
        });
    });
});
