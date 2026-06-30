let serverInfo = null;

async function fetchAPI(url, options = {}) {
    const response = await fetch(url, options);
    return response;
}

async function loadServerStatus() {
    try {
        const response = await fetchAPI('/api/status');
        if (response.ok) {
            serverInfo = await response.json();
            updateConnectionUI();
            return;
        }
    } catch (e) {
        // fallback
    }
    // If /api/status doesn't exist yet, derive from location
    serverInfo = {
        port: window.location.port || '8080',
        host: window.location.hostname || '127.0.0.1',
        tls: window.location.protocol === 'https:',
        version: 'v1.5.0',
        config_loaded: true,
        tools_available: '--'
    };
    updateConnectionUI();
}

function updateConnectionUI() {
    if (!serverInfo) return;

    const proto = serverInfo.tls ? 'https' : 'http';
    const addr = serverInfo.host + ':' + serverInfo.port;
    const fullUrl = proto + '://' + addr;

    document.getElementById('connection-dot').className = 'h-2 w-2 rounded-full bg-emerald-500 animate-pulse shadow-lg shadow-emerald-500/50';
    document.getElementById('connection-label').textContent = 'Connected';
    document.getElementById('connection-label').className = 'text-[10px] font-mono text-emerald-400 uppercase';
    document.getElementById('server-addr').textContent = fullUrl;
    document.getElementById('dashboard-url').textContent = fullUrl;
    document.getElementById('cli-scan-cmd').textContent = 'bbpts -t <target> --web';
}

function switchTab(tabId) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('panel-active'));
    document.querySelectorAll('.nav-item').forEach(n => {
        n.classList.remove('nav-active');
        n.classList.add('text-slate-400');
    });

    document.getElementById('panel-' + tabId).classList.add('panel-active');
    const navLink = document.getElementById('nav-' + tabId);
    navLink.classList.add('nav-active');
    navLink.classList.remove('text-slate-400');

    if (tabId === 'config') loadConfig();
    if (tabId === 'triage') loadFindings();
}

async function refreshData() {
    try {
        const [statsResp, scansResp] = await Promise.all([
            fetchAPI('/api/stats'),
            fetchAPI('/api/scans')
        ]);

        if (!statsResp.ok || !scansResp.ok) return;

        const stats = await statsResp.json();
        const scans = await scansResp.json();

        document.getElementById('stat-targets').innerText = (stats.total_targets || 0).toLocaleString();
        document.getElementById('stat-scans').innerText = stats.total_scans || 0;
        document.getElementById('stat-critical').innerText = stats.critical_vulns || 0;

        if (stats.tools_available !== undefined) {
            document.getElementById('stat-tools').innerText = stats.tools_available;
        }

        const tbody = document.getElementById('scan-history');
        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="py-8 text-center text-slate-600 font-mono text-xs">No scans yet. Run <span class="text-cyan-400">bbpts -t &lt;target&gt;</span> to start.</td></tr>';
            document.getElementById('scan-count').textContent = '0 total';
        } else {
            document.getElementById('scan-count').textContent = scans.length + ' total';
            tbody.innerHTML = scans.slice(0, 8).map(s => `
                <tr class="hover:bg-slate-800/30 transition-colors border-b border-slate-800/40">
                    <td class="py-3 pl-2">
                        <p class="text-sm font-semibold text-slate-100">${escapeHtml(s.scope || s.target || 'N/A')}</p>
                        <p class="text-[10px] text-slate-500 font-mono">ID: #${s.id}</p>
                    </td>
                    <td class="py-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${s.status === 'completed' ? 'badge-info' : s.status === 'running' ? 'badge-running' : 'badge-high'}">
                            ${escapeHtml(s.status || 'unknown')}
                        </span>
                    </td>
                    <td class="py-3 pr-2 text-slate-400 text-[10px] uppercase font-mono">${s.start_time ? new Date(s.start_time).toLocaleString() : '--'}</td>
                </tr>
            `).join('');
        }

        initChart(stats);
    } catch (e) {
        console.error('refreshData error:', e);
    }
}

let chart = null;
function initChart(stats) {
    const ctx = document.getElementById('surface-chart').getContext('2d');
    if (chart) chart.destroy();

    const hasData = stats && (
        (stats.total_targets || 0) > 0 ||
        (stats.total_scans || 0) > 0
    );

    document.getElementById('chart-empty-msg').style.display = hasData ? 'none' : 'block';

    chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Subdomains', 'Cloud', 'Exposures', 'Other'],
            datasets: [{
                data: hasData ? [stats.subdomains || 45, stats.cloud || 28, stats.exposures || 12, stats.other || 15] : [1],
                backgroundColor: hasData ? ['#06b6d4', '#6366f1', '#ef4444', '#4b5563'] : ['#1f2937'],
                hoverOffset: 10,
                borderWidth: 0
            }]
        },
        options: {
            cutout: '80%',
            plugins: { legend: { display: false } },
            maintainAspectRatio: false
        }
    });
}

// --- Log Streaming ---
let eventSource = null;
function startLogStream() {
    if (eventSource) eventSource.close();

    const statusIndicator = document.getElementById('log-status');
    const terminal = document.getElementById('log-terminal');
    eventSource = new EventSource('/api/logs/stream');

    eventSource.onopen = () => {
        statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase badge-info';
        statusIndicator.innerText = 'Connected';
    };

    eventSource.onerror = () => {
        statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase badge-critical';
        statusIndicator.innerText = 'Disconnected';
    };

    eventSource.onmessage = (event) => {
        const line = document.createElement('div');
        line.className = 'py-0.5 border-b border-slate-900/40 hover:bg-slate-900/20 px-2 font-mono';
        line.textContent = event.data;
        terminal.appendChild(line);

        if (document.getElementById('log-autoscroll').checked) {
            terminal.scrollTop = terminal.scrollHeight;
        }
    };
}

function clearLogs() {
    document.getElementById('log-terminal').innerHTML = '';
}

// --- Configuration Management ---
let currentRawConfig = null;

async function loadConfig() {
    try {
        const response = await fetchAPI('/api/config');
        if (!response.ok) return;
        const cfg = await response.json();
        currentRawConfig = cfg;

        document.getElementById('cfg-container-mode').checked = !!cfg.container_mode;
        document.getElementById('cfg-rate-limit').value = cfg.rate_limit || 0;
        document.getElementById('cfg-threads').value = cfg.threads || 0;
        document.getElementById('cfg-batch-size').value = cfg.batch_size || 0;
        document.getElementById('cfg-wordlists-dir').value = cfg.wordlists_dir || '';
        document.getElementById('cfg-state-dir').value = cfg.state_dir || '';

        if (cfg.wordlists) {
            document.getElementById('cfg-wl-dns').value = cfg.wordlists.dns || '';
            document.getElementById('cfg-wl-dir').value = cfg.wordlists.directory || '';
            document.getElementById('cfg-wl-subdomain').value = cfg.wordlists.subdomain || '';
            document.getElementById('cfg-wl-api').value = cfg.wordlists.api || '';
        }

        if (cfg.fleet) {
            document.getElementById('cfg-fleet-sync-token').value = cfg.fleet.sync_token || '';
        }

        const apiKeysContainer = document.getElementById('api-keys-container');
        apiKeysContainer.innerHTML = '';
        const providers = ['shodan', 'censys', 'securitytrails', 'github', 'chaos', 'virustotal', 'passivetotal', 'binaryedge'];
        const keys = cfg.api_keys || {};

        providers.forEach(p => {
            const hasKey = keys[p] && keys[p] !== '';
            const div = document.createElement('div');
            div.innerHTML = `
                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 font-mono">${p} ${hasKey ? '<span class="text-emerald-500">(set)</span>' : '<span class="text-slate-600">(empty)</span>'}</label>
                <input type="password" data-provider="${p}" value="${keys[p] || ''}" placeholder="${hasKey ? 'Enter new key to update' : 'Optional API key'}" class="cfg-api-key w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none font-mono">
            `;
            apiKeysContainer.appendChild(div);
        });
    } catch (e) {
        console.error('loadConfig error:', e);
    }
}

async function saveConfig() {
    if (!currentRawConfig) return;

    currentRawConfig.container_mode = document.getElementById('cfg-container-mode').checked;
    currentRawConfig.rate_limit = parseInt(document.getElementById('cfg-rate-limit').value, 10) || 0;
    currentRawConfig.threads = parseInt(document.getElementById('cfg-threads').value, 10) || 0;
    currentRawConfig.batch_size = parseInt(document.getElementById('cfg-batch-size').value, 10) || 0;
    currentRawConfig.wordlists_dir = document.getElementById('cfg-wordlists-dir').value;
    currentRawConfig.state_dir = document.getElementById('cfg-state-dir').value;

    if (!currentRawConfig.wordlists) currentRawConfig.wordlists = {};
    currentRawConfig.wordlists.dns = document.getElementById('cfg-wl-dns').value;
    currentRawConfig.wordlists.directory = document.getElementById('cfg-wl-dir').value;
    currentRawConfig.wordlists.subdomain = document.getElementById('cfg-wl-subdomain').value;
    currentRawConfig.wordlists.api = document.getElementById('cfg-wl-api').value;

    if (!currentRawConfig.fleet) currentRawConfig.fleet = {};
    currentRawConfig.fleet.sync_token = document.getElementById('cfg-fleet-sync-token').value;

    if (!currentRawConfig.api_keys) currentRawConfig.api_keys = {};
    document.querySelectorAll('.cfg-api-key').forEach(input => {
        const provider = input.getAttribute('data-provider');
        currentRawConfig.api_keys[provider] = input.value;
    });

    try {
        const response = await fetchAPI('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentRawConfig)
        });
        const result = await response.json();
        if (response.ok) {
            showToast('Configuration saved successfully');
        } else {
            showToast(result.error || 'Failed to save', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function loadFindings() {
    try {
        const response = await fetchAPI('/api/findings');
        if (!response.ok) return;
        const findings = await response.json();
        const tbody = document.getElementById('triage-findings-body');
        tbody.innerHTML = '';
        if (!findings || findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-slate-600 font-mono text-xs">No findings yet. Run a scan to discover vulnerabilities.</td></tr>';
            return;
        }
        findings.forEach(f => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-800/30 transition-colors border-b border-slate-800/40';
            tr.innerHTML = `
                <td class="py-4 pr-4 pl-2">
                    <p class="text-sm font-semibold text-slate-100 font-mono">${escapeHtml(f.target || 'N/A')}</p>
                    <p class="text-xs text-slate-400 mt-0.5 font-semibold">${escapeHtml(f.title || 'N/A')}</p>
                    <p class="text-[10px] text-slate-500 mt-1 font-mono">${escapeHtml(f.description || '')}</p>
                </td>
                <td class="py-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityClass(f.severity)}">
                        ${escapeHtml(f.severity || 'info')}
                    </span>
                </td>
                <td class="py-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 font-mono">
                        ${escapeHtml(f.workflow_state || 'Discovered')}
                    </span>
                </td>
                <td class="py-4 pr-2">
                    <div class="flex gap-2 items-center">
                        <select id="sev-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-semibold">
                            <option value="critical" ${f.severity === 'critical' ? 'selected' : ''}>Critical</option>
                            <option value="high" ${f.severity === 'high' ? 'selected' : ''}>High</option>
                            <option value="medium" ${f.severity === 'medium' ? 'selected' : ''}>Medium</option>
                            <option value="low" ${f.severity === 'low' ? 'selected' : ''}>Low</option>
                            <option value="info" ${f.severity === 'info' ? 'selected' : ''}>Info</option>
                        </select>
                        <select id="state-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-semibold">
                            <option value="Discovered" ${f.workflow_state === 'Discovered' ? 'selected' : ''}>Discovered</option>
                            <option value="Triaged" ${f.workflow_state === 'Triaged' ? 'selected' : ''}>Triaged</option>
                            <option value="Remediating" ${f.workflow_state === 'Remediating' ? 'selected' : ''}>Remediating</option>
                            <option value="SLA Exception" ${f.workflow_state === 'SLA Exception' ? 'selected' : ''}>SLA Exception</option>
                        </select>
                        <button onclick="overrideFindingTriage(${f.id})" class="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs px-3 py-1.5 rounded transition shadow-md shadow-cyan-900/20">Save</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('loadFindings error:', e);
    }
}

function getSeverityClass(sev) {
    if (!sev) return 'badge-info';
    switch (sev.toLowerCase()) {
        case 'critical': return 'badge-critical';
        case 'high': return 'badge-high';
        case 'medium': return 'badge-medium';
        case 'low': return 'badge-low';
        default: return 'badge-info';
    }
}

async function overrideFindingTriage(id) {
    const sev = document.getElementById('sev-' + id).value;
    const state = document.getElementById('state-' + id).value;
    try {
        const response = await fetchAPI('/api/findings/triage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, severity: sev, workflow_state: state })
        });
        const result = await response.json();
        if (response.ok) {
            showToast('Finding updated');
            loadFindings();
        } else {
            showToast(result.error || 'Failed to update', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function startNewScan() {
    showToast('Use the CLI: bbpts -t <target> --web', 'info');
}

function dismissQuickStart() {
    document.getElementById('quick-start-banner').classList.add('hidden');
    try { localStorage.setItem('bbpts_quickstart_dismissed', '1'); } catch (e) {}
}

function showToast(msg, type) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg text-xs font-mono font-bold shadow-xl transition-all duration-300 ' +
        (type === 'error' ? 'bg-rose-600 text-white' : 'bg-cyan-600 text-white');
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

window.onload = () => {
    loadServerStatus().then(() => {
        refreshData();
        startLogStream();
        const dismissed = localStorage.getItem('bbpts_quickstart_dismissed');
        if (!dismissed) {
            document.getElementById('quick-start-banner').classList.remove('hidden');
        }
    });
};
setInterval(refreshData, 10000);
