// wiki.js - External JavaScript file for the wiki

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    // Attach event listeners to toolbar buttons
    const btnBold = document.getElementById('btn-bold');
    const btnItalic = document.getElementById('btn-italic');
    const btnLink = document.getElementById('btn-link');
    const btnHelp = document.getElementById('btn-help');
    const imageUpload = document.getElementById('image-upload');
    
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
});

function uploadImage() {
    // Show uploading message
    const toolbar = document.getElementById('toolbar');
    let uploadStatus = document.getElementById('upload-status');
    
    if (!uploadStatus) {
        uploadStatus = document.createElement('span');
        uploadStatus.id = 'upload-status';
        uploadStatus.style.marginLeft = '1em';
        toolbar.appendChild(uploadStatus);
    }
    
    uploadStatus.style.color = '#0066cc';
    uploadStatus.textContent = 'â³ Uploading...';
    
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
            uploadStatus.textContent = 'âœ“ Image inserted!';
            uploadStatus.style.color = '#28a745';
            setTimeout(() => uploadStatus.remove(), 3000);
        } else {
            // Show error
            uploadStatus.textContent = 'âœ— Upload failed';
            uploadStatus.style.color = '#dc3545';
        }
        
        // Reset file input
        document.getElementById('image-upload').value = '';
    })
    .catch(error => {
        uploadStatus.textContent = 'âœ— Upload error';
        uploadStatus.style.color = '#dc3545';
        console.error('Upload error:', error);
    });
}

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
}

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
