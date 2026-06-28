let currentUser = null;

async function fetchAPI(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401) {
        document.getElementById('login-modal').classList.remove('hidden');
        throw new Error('Unauthorized');
    }
    return response;
}

async function checkAuth() {
    try {
        const response = await fetch('/api/me');
        if (response.ok) {
            const data = await response.json();
            currentUser = data;
            document.getElementById('login-modal').classList.add('hidden');
            updateUserUI();
            refreshData();
            startLogStream();
        } else {
            document.getElementById('login-modal').classList.remove('hidden');
        }
    } catch (e) {
        document.getElementById('login-modal').classList.remove('hidden');
    }
}

async function submitLogin() {
    const userVal = document.getElementById('login-username').value;
    const passVal = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    errEl.classList.add('hidden');
    try {
        const response = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: userVal, password: passVal })
        });
        if (response.ok) {
            document.getElementById('login-modal').classList.add('hidden');
            await checkAuth();
        } else {
            const data = await response.json();
            errEl.innerText = data.error || 'Authentication failed';
            errEl.classList.remove('hidden');
        }
    } catch (e) {
        errEl.innerText = 'Network error: ' + e.message;
        errEl.classList.remove('hidden');
    }
}

async function logout() {
    try {
        await fetchAPI('/api/logout', { method: 'POST' });
    } catch (e) {
        console.error(e);
    }
    currentUser = null;
    document.getElementById('login-modal').classList.remove('hidden');
}

function updateUserUI() {
    const username = (currentUser && currentUser.username) || 'Guest';
    const role = (currentUser && currentUser.role) || 'Unknown';
    document.getElementById('user-display-name').innerText = username;
    document.getElementById('user-display-role').innerText = role.toUpperCase() + ' OPERATOR';
    if (username && username.length > 0) {
        document.getElementById('user-avatar').innerText = username.substring(0, 2).toUpperCase();
    }
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

    if (tabId === 'config') {
        loadConfig();
    }
    if (tabId === 'triage') {
        loadFindings();
    }
}

async function refreshData() {
    try {
        const [statsResp, scansResp] = await Promise.all([
            fetchAPI('/api/stats'),
            fetchAPI('/api/scans')
        ]);
        
        const stats = await statsResp.json();
        const scans = await scansResp.json();
        
        document.getElementById('stat-targets').innerText = stats.total_targets.toLocaleString();
        document.getElementById('stat-scans').innerText = stats.total_scans;
        document.getElementById('stat-critical').innerText = stats.critical_vulns;
        
        const tbody = document.getElementById('scan-history');
        tbody.innerHTML = scans.slice(0, 5).map(s => `
            <tr class="hover:bg-slate-800/30 transition-colors">
                <td class="py-4">
                    <p class="text-sm font-semibold">${s.scope}</p>
                    <p class="text-[10px] text-slate-500">SCAN_ID: #${s.id}</p>
                </td>
                <td class="py-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}">
                        ${s.status}
                    </span>
                </td>
                <td class="py-4 text-slate-400 text-[10px] uppercase">${new Date(s.start_time).toLocaleTimeString()}</td>
            </tr>
        `).join('');

        initChart();
    } catch (e) { console.error(e); }
}

let chart = null;
function initChart() {
    const ctx = document.getElementById('surface-chart').getContext('2d');
    if (chart) chart.destroy();
    chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Subdomains', 'Cloud', 'Exposures', 'Other'],
            datasets: [{
                data: [45, 28, 12, 15],
                backgroundColor: ['#bd93f9', '#8be9fd', '#ff5555', '#44475a'],
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
    if (eventSource) {
        eventSource.close();
    }
    const statusIndicator = document.getElementById('log-status');
    const terminal = document.getElementById('log-terminal');
    eventSource = new EventSource('/api/logs/stream');

    eventSource.onopen = () => {
        statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400';
        statusIndicator.innerText = 'Connected';
    };

    eventSource.onerror = (e) => {
        statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/10 text-rose-400';
        statusIndicator.innerText = 'Disconnected';
    };

    eventSource.onmessage = (event) => {
        const line = document.createElement('div');
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
        const cfg = await response.json();
        currentRawConfig = cfg;

        // Set container mode toggle
        document.getElementById('cfg-container-mode').checked = !!cfg.container_mode;

        // Load basic fields
        document.getElementById('cfg-rate-limit').value = cfg.rate_limit || 0;
        document.getElementById('cfg-threads').value = cfg.threads || 0;
        document.getElementById('cfg-batch-size').value = cfg.batch_size || 0;
        document.getElementById('cfg-wordlists-dir').value = cfg.wordlists_dir || '';
        document.getElementById('cfg-state-dir').value = cfg.state_dir || '';

        // Load wordlists
        if (cfg.wordlists) {
            document.getElementById('cfg-wl-dns').value = cfg.wordlists.dns || '';
            document.getElementById('cfg-wl-dir').value = cfg.wordlists.directory || '';
            document.getElementById('cfg-wl-subdomain').value = cfg.wordlists.subdomain || '';
            document.getElementById('cfg-wl-api').value = cfg.wordlists.api || '';
        }

        // Load fleet sync token
        if (cfg.fleet) {
            document.getElementById('cfg-fleet-sync-token').value = cfg.fleet.sync_token || '';
        }

        // Dynamically build API key inputs
        const apiKeysContainer = document.getElementById('api-keys-container');
        apiKeysContainer.innerHTML = '';
        const providers = ['shodan', 'censys', 'securitytrails', 'github', 'chaos', 'virustotal', 'passivetotal', 'binaryedge'];
        const keys = cfg.api_keys || {};
        
        providers.forEach(p => {
            const div = document.createElement('div');
            div.innerHTML = `
                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">${p}</label>
                <input type="password" data-provider="${p}" value="${keys[p] || ''}" class="cfg-api-key w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
            `;
            apiKeysContainer.appendChild(div);
        });
    } catch (e) {
        console.error('Error loading configuration: ', e);
    }
}

async function saveConfig() {
    if (!currentRawConfig) return;

    // Merge form values back to currentRawConfig
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
            alert('Configuration saved successfully!');
        } else {
            throw new Error(result.error || 'Failed to save');
        }
    } catch (e) {
        alert('Error saving configuration: ' + e.message);
    }
}

async function loadFindings() {
    try {
        const response = await fetchAPI('/api/findings');
        const findings = await response.json();
        const tbody = document.getElementById('triage-findings-body');
        tbody.innerHTML = '';
        if (!findings || findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-slate-500">No findings registered yet.</td></tr>';
            return;
        }
        findings.forEach(f => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-800/30 transition-colors border-b border-slate-800/50';
            tr.innerHTML = `
                <td class="py-4 pr-4">
                    <p class="text-sm font-semibold text-slate-200">${f.target || 'N/A'}</p>
                    <p class="text-xs text-slate-400 mt-0.5">${f.title || 'N/A'}</p>
                    <p class="text-[10px] text-slate-500 mt-1">${f.description || ''}</p>
                </td>
                <td class="py-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityClass(f.severity)}">
                        ${f.severity || 'info'}
                    </span>
                </td>
                <td class="py-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                        ${f.workflow_state || 'Discovered'}
                    </span>
                </td>
                <td class="py-4">
                    <div class="flex gap-2 items-center">
                        <select id="sev-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-purple-600">
                            <option value="critical" ${f.severity === 'critical' ? 'selected' : ''}>Critical</option>
                            <option value="high" ${f.severity === 'high' ? 'selected' : ''}>High</option>
                            <option value="medium" ${f.severity === 'medium' ? 'selected' : ''}>Medium</option>
                            <option value="low" ${f.severity === 'low' ? 'selected' : ''}>Low</option>
                            <option value="info" ${f.severity === 'info' ? 'selected' : ''}>Info</option>
                        </select>
                        <select id="state-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-purple-600">
                            <option value="Discovered" ${f.workflow_state === 'Discovered' ? 'selected' : ''}>Discovered</option>
                            <option value="Triaged" ${f.workflow_state === 'Triaged' ? 'selected' : ''}>Triaged</option>
                            <option value="Remediating" ${f.workflow_state === 'Remediating' ? 'selected' : ''}>Remediating</option>
                            <option value="SLA Exception" ${f.workflow_state === 'SLA Exception' ? 'selected' : ''}>SLA Exception</option>
                        </select>
                        <button onclick="overrideFindingTriage(${f.id})" class="bg-purple-600 hover:bg-purple-700 text-white font-semibold text-xs px-2.5 py-1.5 rounded transition">Override</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error loading findings: ', e);
    }
}

function getSeverityClass(sev) {
    if (!sev) return 'bg-slate-700 text-slate-300';
    switch (sev.toLowerCase()) {
        case 'critical': return 'bg-rose-500/10 text-rose-400 border border-rose-500/20';
        case 'high': return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
        case 'medium': return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
        case 'low': return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
        default: return 'bg-slate-800 text-slate-300';
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
            alert('Finding triage updated successfully!');
            loadFindings();
        } else {
            throw new Error(result.error || 'Failed to update');
        }
    } catch (e) {
        alert('Error updating triage: ' + e.message);
    }
}

window.onload = () => {
    checkAuth();
};
setInterval(refreshData, 10000);
