// scanner.js - Handles file upload and scanning

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const progressContainer = document.getElementById('scanner-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressPercent = document.getElementById('scan-percent');
    const statusText = document.getElementById('scan-status-text');
    const errorContainer = document.getElementById('scan-error');
    const errorMsg = document.getElementById('scan-error-msg');

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight dropzone on drag
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.add('dragover'), false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.remove('dragover'), false);
    });

    // Handle drop
    dropzone.addEventListener('drop', handleDrop, false);

    // Handle click upload
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            uploadFile(e.target.files[0]);
        }
    });

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) {
            uploadFile(files[0]);
        }
    }

    function uploadFile(file) {
        // Reset UI
        errorContainer.style.display = 'none';
        progressContainer.style.display = 'block';
        dropzone.style.display = 'none';

        progressFill.style.width = '10%';
        progressPercent.innerText = '10%';
        statusText.innerText = 'Uploading ' + file.name + '...';

        const formData = new FormData();
        formData.append('file', file);

        // Fake progress animation
        let fakeProgress = 10;
        const interval = setInterval(() => {
            if (fakeProgress < 85) {
                fakeProgress += Math.random() * 15;
                if (fakeProgress > 85) fakeProgress = 85;
                progressFill.style.width = fakeProgress + '%';
                progressPercent.innerText = Math.floor(fakeProgress) + '%';

                if (fakeProgress > 40) statusText.innerText = 'Running Static Analysis...';
                if (fakeProgress > 70) statusText.innerText = 'Extracting Indicators of Compromise...';
            }
        }, 500);

        fetch('/api/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) throw new Error('Server error during scan (HTTP ' + response.status + ')');
            return response.json();
        })
        .then(data => {
            clearInterval(interval);
            progressFill.style.width = '100%';
            progressPercent.innerText = '100%';
            statusText.innerText = 'Analysis Complete! Redirecting...';

            // FIX: Store the full report in sessionStorage so report.js can
            // render it without a separate /api/report/ call.
            // This is essential on Vercel where each serverless function has
            // its own isolated /tmp — the DB written by scan.py is NOT
            // readable by report.py (different containers).
            if (data.report) {
                // Add timestamp for display
                data.report.timestamp = new Date().toISOString();
                sessionStorage.setItem('pendingReport', JSON.stringify(data.report));
            }

            const reportId = data.id || 'new';
            setTimeout(() => {
                window.location.href = '/report.html?id=' + reportId;
            }, 1000);
        })
        .catch(err => {
            clearInterval(interval);
            progressContainer.style.display = 'none';
            dropzone.style.display = 'block';
            errorContainer.style.display = 'block';
            errorMsg.innerText = err.message || 'Failed to upload and scan file.';
        });
    }
});
