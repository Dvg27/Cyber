// report.js - Fetches and renders the analysis report

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const reportId = urlParams.get('id');

    if (!reportId) {
        showError('No report ID provided. Please scan a file first.');
        return;
    }

    // FIX: First check sessionStorage for report data cached by scanner.js.
    // On Vercel, each serverless function runs in an isolated container, so
    // the DB written by scan.py is not readable by report.py.
    // scanner.js embeds the full report in the scan response and stores it here.
    const cached = sessionStorage.getItem('pendingReport');
    if (cached) {
        try {
            const reportData = JSON.parse(cached);
            if (String(reportData.id) === String(reportId)) {
                sessionStorage.removeItem('pendingReport');
                renderReport(reportData);
                return;
            }
        } catch (e) {
            sessionStorage.removeItem('pendingReport');
            // Fall through to API call
        }
    }

    // Fallback: try the /api/report/ endpoint (works locally with Flask backend)
    fetch('/api/report/' + reportId)
        .then(res => {
            if (!res.ok) {
                return res.json().then(body => {
                    throw new Error(body.error || 'Report not found (HTTP ' + res.status + ')');
                }).catch(() => {
                    throw new Error('Report not found (HTTP ' + res.status + ')');
                });
            }
            return res.json();
        })
        .then(data => {
            renderReport(data);
        })
        .catch(err => {
            showError(err.message);
        });
});

function showError(message) {
    const loading = document.getElementById('loading');
    loading.innerHTML =
        '<i class="fa-solid fa-triangle-exclamation fa-3x" style="color: var(--accent-red);"></i>' +
        '<h2 style="margin-top:1rem;">Error Loading Report</h2>' +
        '<p style="color: var(--text-muted);">' + message + '</p>' +
        '<a href="/scanner.html" class="btn btn-primary" style="margin-top:1.5rem;">' +
        '<i class="fa-solid fa-microscope"></i> Scan a New File</a>';
}

function renderReport(data) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('report-content').style.display = 'block';

    // File Information
    document.getElementById('rep-filename').innerText = data.filename || '—';
    document.getElementById('rep-size').innerText = formatBytes(data.size);
    document.getElementById('rep-type').innerText = data.type || 'Unknown';
    document.getElementById('rep-md5').innerText = data.md5 || '—';
    document.getElementById('rep-sha256').innerText = data.sha256 || '—';
    const ts = data.timestamp ? new Date(data.timestamp).toLocaleString() : 'Just now';
    document.getElementById('rep-date').innerText = ts;

    // Score & Verdict
    const score = data.score || 0;
    document.getElementById('rep-score').innerText = score;
    const ring = document.getElementById('rep-score-ring');
    const verdict = document.getElementById('rep-verdict');

    if (score >= 70) {
        ring.classList.add('high');
        verdict.classList.add('high');
        verdict.innerHTML = '<i class="fa-solid fa-radiation"></i> HIGH RISK';
    } else if (score >= 30) {
        ring.classList.add('medium');
        verdict.classList.add('medium');
        verdict.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> SUSPICIOUS';
    } else {
        ring.classList.add('low');
        verdict.classList.add('low');
        verdict.innerHTML = '<i class="fa-solid fa-shield-check"></i> CLEAN';
    }

    // Malware Classification & Family
    const malwareType = data.malware_type || 'Clean / Benign';
    const malwareFamily = data.malware_family || 'None';
    const matchedRules = data.matched_rules || [];

    const typeElem = document.getElementById('rep-malware-type');
    const familyElem = document.getElementById('rep-malware-family');
    const typeBadge = document.getElementById('rep-malware-type-badge');
    const typeIcon = document.getElementById('rep-type-icon');

    if (typeElem) typeElem.innerText = malwareType;
    if (familyElem) familyElem.innerText = malwareFamily;

    if (typeBadge && typeIcon) {
        typeBadge.className = 'classification-badge';
        if (malwareType.includes('Ransomware')) {
            typeBadge.classList.add('badge-ransomware');
            typeIcon.className = 'fa-solid fa-skull-crossbones';
        } else if (malwareType.includes('Spyware') || malwareType.includes('InfoStealer')) {
            typeBadge.classList.add('badge-spyware');
            typeIcon.className = 'fa-solid fa-user-secret';
        } else if (malwareType.includes('Keylogger')) {
            typeBadge.classList.add('badge-keylogger');
            typeIcon.className = 'fa-solid fa-keyboard';
        } else if (malwareType.includes('Trojan')) {
            typeBadge.classList.add('badge-trojan');
            typeIcon.className = 'fa-solid fa-horse-head';
        } else if (malwareType.includes('Worm')) {
            typeBadge.classList.add('badge-worm');
            typeIcon.className = 'fa-solid fa-network-wired';
        } else if (malwareType.includes('EICAR')) {
            typeBadge.classList.add('badge-eicar');
            typeIcon.className = 'fa-solid fa-vial-virus';
        } else if (malwareType.includes('Clean')) {
            typeBadge.classList.add('badge-clean');
            typeIcon.className = 'fa-solid fa-shield-check';
        } else {
            typeBadge.classList.add('badge-suspicious');
            typeIcon.className = 'fa-solid fa-triangle-exclamation';
        }
    }

    // Render Matched Behavioral Rules
    const rulesContainer = document.getElementById('rep-matched-rules');
    if (rulesContainer) {
        if (matchedRules.length > 0) {
            rulesContainer.innerHTML = '';
            matchedRules.forEach(r => {
                const sev = r.severity || 'HIGH';
                const sevClass = (sev === 'CRITICAL') ? 'err' : ((sev === 'HIGH') ? 'warn' : 'info');
                const ruleItem = document.createElement('div');
                ruleItem.className = 'rule-item ' + sevClass;
                
                let matchesHtml = '';
                if (r.matches && r.matches.length > 0) {
                    const safeMatches = r.matches.map(m => String(m).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')).join(' | ');
                    matchesHtml = `<div class="rule-matches"><i class="fa-solid fa-terminal"></i> Pattern: <code>${safeMatches}</code></div>`;
                }

                ruleItem.innerHTML = `
                    <div class="rule-title">
                        <span class="rule-badge ${sevClass}">${sev}</span>
                        <strong>${String(r.name || 'Rule').replace(/&/g, '&amp;').replace(/</g, '&lt;')}</strong>
                    </div>
                    <div class="rule-desc">${String(r.desc || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')}</div>
                    ${matchesHtml}
                `;
                rulesContainer.appendChild(ruleItem);
            });
        } else {
            rulesContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">No suspicious behavioral threat rules triggered.</p>';
        }
    }

    // Recommendation
    document.getElementById('rep-recommendation').innerText =
        data.recommendation || 'No specific recommendations.';

    // Static Analysis Terminal Output
    const details = document.getElementById('rep-static-details');
    let staticHtml = '<span class="info">[INFO] Initializing static analysis module...</span>\n';
    staticHtml += '<span class="info">[INFO] Extracting PE Headers...</span>\n';
    staticHtml += '<span class="info">[INFO] Analyzing imports and sections...</span>\n';

    if (data.static_details && data.static_details.length > 0) {
        data.static_details.forEach(line => {
            // Escape HTML to prevent XSS from filenames/paths in output
            const escaped = line
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            let cssClass = 'info';
            if (line.startsWith('[WARN]') || line.includes('Suspicious') || line.includes('Warning')) {
                cssClass = 'warn';
            }
            if (line.startsWith('[ERR]') || line.includes('Malicious') || line.includes('Detected')) {
                cssClass = 'err';
            }
            staticHtml += '<span class="' + cssClass + '">' + escaped + '</span>\n';
        });
    }
    details.innerHTML = staticHtml.replace(/\n/g, '<br>');

    // IoCs
    const iocContainer = document.getElementById('rep-iocs');
    if (data.iocs && data.iocs.length > 0) {
        iocContainer.innerHTML = '';
        data.iocs.forEach(ioc => {
            let typeIcon = 'fa-cube';
            let color = 'var(--text-secondary)';
            if (ioc.type === 'ip')   { typeIcon = 'fa-network-wired'; color = 'var(--accent-blue)'; }
            if (ioc.type === 'url')  { typeIcon = 'fa-link';          color = 'var(--accent-purple)'; }
            if (ioc.type === 'hash') { typeIcon = 'fa-hashtag';       color = 'var(--accent-red)'; }

            // Escape IoC value to prevent XSS
            const safeValue = String(ioc.value)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            const safeType = String(ioc.type).toUpperCase()
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

            iocContainer.innerHTML +=
                '<div class="kv-pair">' +
                  '<span class="kv-key" style="color: ' + color + ';">' +
                    '<i class="fa-solid ' + typeIcon + '"></i> ' + safeType +
                  '</span>' +
                  '<span class="kv-value ' + (ioc.type === 'hash' ? 'hash-font' : '') + '">' +
                    safeValue +
                  '</span>' +
                '</div>';
        });
    } else {
        iocContainer.innerHTML = '<p style="color: var(--text-muted); text-align: center;">No IoCs found.</p>';
    }
}
