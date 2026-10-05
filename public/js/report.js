// report.js - Fetches and renders report

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const reportId = urlParams.get('id');

    if (!reportId) {
        document.getElementById('loading').innerHTML = '<h2>No report ID provided</h2><p>Please scan a file first.</p>';
        return;
    }

    fetch(`/api/report/${reportId}`)
        .then(res => {
            if (!res.ok) throw new Error('Report not found');
            return res.json();
        })
        .then(data => {
            renderReport(data);
        })
        .catch(err => {
            document.getElementById('loading').innerHTML = `<h2>Error</h2><p>${err.message}</p>`;
        });
});

function renderReport(data) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('report-content').style.display = 'block';

    // File Info
    document.getElementById('rep-filename').innerText = data.filename;
    document.getElementById('rep-size').innerText = formatBytes(data.size);
    document.getElementById('rep-type').innerText = data.type || 'Unknown';
    document.getElementById('rep-md5').innerText = data.md5;
    document.getElementById('rep-sha256').innerText = data.sha256;
    document.getElementById('rep-date').innerText = new Date(data.timestamp).toLocaleString();

    // Score & Verdict
    const score = data.score;
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

    // Recommendation
    document.getElementById('rep-recommendation').innerText = data.recommendation || 'No specific recommendations.';

    // Static Details
    const details = document.getElementById('rep-static-details');
    let staticHtml = `[INFO] Initializing static analysis module...\n`;
    staticHtml += `[INFO] Extracting PE Headers...\n`;
    staticHtml += `[INFO] Analyzing imports and sections...\n`;
    
    if (data.static_details) {
        data.static_details.forEach(line => {
            let cssClass = 'info';
            if (line.includes('Suspicious') || line.includes('Warning')) cssClass = 'warn';
            if (line.includes('Malicious') || line.includes('Detected')) cssClass = 'err';
            staticHtml += `<span class="${cssClass}">${line}</span>\n`;
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
            if(ioc.type === 'ip') { typeIcon = 'fa-network-wired'; color = 'var(--accent-blue)'; }
            if(ioc.type === 'url') { typeIcon = 'fa-link'; color = 'var(--accent-purple)'; }
            if(ioc.type === 'hash') { typeIcon = 'fa-hashtag'; color = 'var(--accent-red)'; }

            iocContainer.innerHTML += `
                <div class="kv-pair">
                    <span class="kv-key" style="color: ${color};"><i class="fa-solid ${typeIcon}"></i> ${ioc.type.toUpperCase()}</span>
                    <span class="kv-value ${ioc.type === 'hash' ? 'hash-font' : ''}">${ioc.value}</span>
                </div>
            `;
        });
    }
}
