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
            return response.json().catch(() => ({})).then(data => {
                if (!response.ok) {
                    throw new Error(data.error || 'Server error during scan (HTTP ' + response.status + ')');
                }
                return data;
            });
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

            if (!data.report || data.id === null || data.id === undefined) {
                throw new Error('The server returned an incomplete scan report.');
            }
            const reportId = data.id;
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

    // Load and render Safe Test Samples Catalog
    loadSamplesCatalog();

    async function loadSamplesCatalog() {
        const grid = document.getElementById('samples-grid');
        if (!grid) return;

        const defaultCatalog = [
            {
                id: "eicar",
                filename: "01_eicar_test_sample.txt",
                category: "EICAR Antivirus Standard",
                expected_type: "EICAR Standard Test File",
                badge_class: "badge-eicar",
                icon: "fa-vial-virus",
                threat_level: "Score: 100",
                description: "Standard industry benign test string used worldwide to verify AV and scanner detection pipelines safely without malware risks."
            },
            {
                id: "ransomware",
                filename: "02_ransomware_simulation_sample.txt",
                category: "Ransomware Simulation",
                expected_type: "Ransomware",
                badge_class: "badge-ransomware",
                icon: "fa-skull-crossbones",
                threat_level: "Score: 100",
                description: "Safe simulated sample with shadow copy deletion commands, ransom note phrases, and file encryption APIs."
            },
            {
                id: "infostealer",
                filename: "03_infostealer_simulation_sample.txt",
                category: "Spyware / InfoStealer",
                expected_type: "Spyware / InfoStealer",
                badge_class: "badge-spyware",
                icon: "fa-user-secret",
                threat_level: "Score: 100",
                description: "Safe simulated sample targeting browser password vaults, DPAPI extraction APIs, and crypto wallets."
            },
            {
                id: "trojan",
                filename: "04_trojan_dropper_simulation_sample.txt",
                category: "Trojan / Dropper Simulation",
                expected_type: "Trojan / Dropper",
                badge_class: "badge-trojan",
                icon: "fa-horse-head",
                threat_level: "Score: 100",
                description: "Safe simulated sample with process memory injection (VirtualAllocEx), downloader commands, and reverse shell markers."
            },
            {
                id: "keylogger",
                filename: "05_keylogger_simulation_sample.txt",
                category: "Keylogger Simulation",
                expected_type: "Keylogger",
                badge_class: "badge-keylogger",
                icon: "fa-keyboard",
                threat_level: "Score: 100",
                description: "Safe simulated sample with SetWindowsHookEx keyboard hook APIs and keystroke buffer artifacts."
            },
            {
                id: "clean",
                filename: "06_clean_document_sample.txt",
                category: "Benign Clean Document",
                expected_type: "Clean / Benign",
                badge_class: "badge-clean",
                icon: "fa-shield-check",
                threat_level: "Score: 0",
                description: "Harmless plain text business memo containing zero malicious indicators to demonstrate clean file analysis."
            }
        ];

        let catalog = defaultCatalog;
        try {
            const res = await fetch('/api/samples');
            if (res.ok) {
                const apiData = await res.json();
                if (Array.isArray(apiData) && apiData.length > 0) {
                    catalog = apiData.map(item => {
                        const fallback = defaultCatalog.find(d => d.filename === item.filename) || {};
                        return { ...fallback, ...item };
                    });
                }
            }
        } catch (e) {
            // Use default catalog on network failure
        }

        grid.innerHTML = '';
        catalog.forEach(item => {
            const card = document.createElement('div');
            card.className = 'sample-card';
            card.innerHTML = `
                <div>
                    <div class="sample-card-header">
                        <div>
                            <div class="sample-title">${item.category}</div>
                            <div class="sample-filename">${item.filename}</div>
                        </div>
                        <span class="badge ${item.expected_type && item.expected_type.includes('Clean') ? 'low' : 'high'}" style="font-size: 0.72rem;">
                            ${item.threat_level || 'Test'}
                        </span>
                    </div>
                    <p class="sample-desc" style="margin-top: 0.6rem;">${item.description}</p>
                </div>
                <div class="sample-actions">
                    <button class="btn-sm btn-scan-sample" data-filename="${item.filename}">
                        <i class="fa-solid fa-play"></i> Scan Instantly
                    </button>
                    <a href="/samples/${item.filename}" download="${item.filename}" class="btn-sm btn-download-sample" title="Download test file">
                        <i class="fa-solid fa-download"></i> Download
                    </a>
                </div>
            `;
            grid.appendChild(card);
        });

        // Attach Instant Scan click listeners
        grid.querySelectorAll('.btn-scan-sample').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const filename = e.currentTarget.getAttribute('data-filename');
                try {
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Fetching...';
                    
                    // Fetch sample file content
                    let fileBlob;
                    let resp = await fetch('/samples/' + filename);
                    if (!resp.ok) {
                        resp = await fetch('/api/samples/' + filename);
                    }
                    if (resp.ok) {
                        fileBlob = await resp.blob();
                    } else {
                        throw new Error('Could not load sample file from server.');
                    }

                    const sampleFile = new File([fileBlob], filename, { type: 'text/plain' });
                    // Scroll to top and execute upload
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                    uploadFile(sampleFile);
                } catch (err) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-play"></i> Scan Instantly';
                    alert('Error loading sample: ' + err.message);
                }
            });
        });
    }
});

