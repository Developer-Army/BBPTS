let serverInfo = null;

async function fetchAPI(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401 && !url.includes('/api/auth')) {
        showLoginOverlay();
    }
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
    document.getElementById('cli-scan-cmd').textContent = 'bbpts -i <target> --web';
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
            tbody.innerHTML = '<tr><td colspan="3" class="py-8 text-center text-slate-600 font-mono text-xs">No scans yet. Run <span class="text-cyan-400">bbpts -i &lt;target&gt;</span> to start.</td></tr>';
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

const remediationGuides = {
    "introspection": {
        impact: "Allows arbitrary users to view the entire GraphQL schema layout, query types, mutations, and field relationships, significantly easing vulnerability discovery.",
        remediation: "Disable introspection in production environments. For Apollo Server:\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: false,\n});\n\nFor graphql-go, omit the __schema field resolver.",
        references: ["https://graphql.org/learn/security/", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"]
    },
    "batching": {
        impact: "Allows multiple GraphQL queries to run in a single HTTP request, potentially bypassing traditional HTTP rate-limiting controls and enabling brute-force attacks.",
        remediation: "Implement query batching limits or disable batching entirely. In Apollo Server, set allowBatchedHttpRequests: false. Otherwise, restrict the maximum number of batched operations (e.g. max 5-10 queries per request).",
        references: ["https://www.apollographql.com/docs/apollo-server/performance/apq/", "https://crashtest-security.com/graphql-batch-limit/"]
    },
    "takeover": {
        impact: "Enables an attacker to point their own resources to a dangling domain pointer (CNAME pointing to an unused Cloud/SaaS resource), hijacking traffic, stealing cookies, or launching phishing campaigns.",
        remediation: "Remove the CNAME pointer or DNS record in your DNS zone manager (e.g. Cloudflare, AWS Route53) if the target service is no longer active, or register the service identifier on the third-party platform.",
        references: ["https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeover", "https://github.com/EdOverflow/can-i-take-over-xyz"]
    },
    "cors": {
        impact: "Allows cross-origin requests from arbitrary origins, letting malicious sites read sensitive session data or retrieve API payloads on behalf of authenticated users.",
        remediation: "Do not set Access-Control-Allow-Origin: * concurrently with Access-Control-Allow-Credentials: true. Implement a strict whitelist of trusted origins and return dynamically generated headers only for whitelisted domains.",
        references: ["https://portswigger.net/web-security/cors", "https://owasp.org/www-community/attacks/CORS_Origin_Validation_Bypass"]
    },
    "redirect": {
        impact: "Allows attackers to construct links that redirect users to external malicious domains, facilitating high-credibility credential harvesting and phishing attacks.",
        remediation: "Implement strict destination URL validation. Do not accept arbitrary URLs in parameter redirects. Whitelist target paths, or enforce an intermediate warning page if users are leaving the application domain.",
        references: ["https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging_and_Monitoring"]
    },
    "403": {
        impact: "Sensitive administrative directories or backend functions are exposed through HTTP proxy header overrides or rewrite bypass patterns.",
        remediation: "Verify authorization checks are performed at the application layer rather than relying purely on WAF or web server routing rules. Ensure proxy headers (e.g., X-Original-URL, X-Forwarded-For) are stripped or validated at the gateway.",
        references: ["https://portswigger.net/web-security/access-control"]
    },
    "jwt": {
        impact: "Allows signatures to be forged or algorithm verification bypassed, enabling privilege escalation to administrator roles.",
        remediation: "Do not support none algorithm in JWT verification. Ensure strong signing keys are used (e.g., HS256 with 256-bit secrets, or RS256/ES256 asymmetric keys). Validate the exp (expiration) and aud (audience) claims.",
        references: ["https://jwt.io/introduction", "https://portswigger.net/web-security/jwt"]
    },
    "race": {
        impact: "Enables transaction/limit bypasses or parallel state checks, letting attackers double-spend, reuse single-use gift cards, or duplicate votes.",
        remediation: "Implement database transactions, optimistic locking, or distributed locks (e.g., Redis Redlock) to serialize access to state-changing operations.",
        references: ["https://owasp.org/www-community/vulnerabilities/Race_Condition"]
    },
    "bypass": {
        impact: "Bypasses rate limiting or application locks via client-side request manipulation (e.g., custom headers).",
        remediation: "Enforce strict server-side rate limits using IP address + session identifier/API key tokens, rather than relying solely on HTTP headers.",
        references: ["https://owasp.org/www-community/controls/Rate_Limiting"]
    },
    "secret": {
        impact: "Exposes private API tokens, database passwords, private keys, or SSH credentials, potentially leading to complete infrastructure compromise.",
        remediation: "Immediately revoke the exposed secret. Rotate all affected tokens or keys. Implement secret scanners in CI/CD pipelines (e.g. git-secrets, TruffleHog) to prevent future commits of raw secrets.",
        references: ["https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure"]
    },
    "vulnerability": {
        impact: "Indicates a software component has a known vulnerability or misconfiguration exposing it to remote execution or privilege escalation.",
        remediation: "Ensure the package or server component is upgraded to the latest security patch. Follow standard secure configuration hardening procedures.",
        references: ["https://nvd.nist.gov/", "https://owasp.org/www-project-top-ten/"]
    }
};

function getRemediation(title, desc) {
    const titleLower = (title || "").toLowerCase();
    const descLower = (desc || "").toLowerCase();
    for (const key in remediationGuides) {
        if (titleLower.includes(key) || descLower.includes(key)) {
            return remediationGuides[key];
        }
    }
    return remediationGuides["vulnerability"];
}

function toggleRemediation(id) {
    const el = document.getElementById(`remediation-tr-${id}`);
    if (el) {
        el.classList.toggle('expanded');
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
            tr.className = 'hover:bg-slate-800/30 transition-colors border-b border-slate-800/40 cursor-pointer';
            tr.onclick = (e) => {
                if (e.target.tagName === 'SELECT' || e.target.tagName === 'BUTTON' || e.target.tagName === 'OPTION') {
                    return;
                }
                toggleRemediation(f.id);
            };
            tr.innerHTML = `
                <td class="py-4 pr-4 pl-2">
                    <p class="text-sm font-semibold text-slate-100 font-mono">${escapeHtml(f.target || 'N/A')}</p>
                    <p class="text-xs text-slate-400 mt-0.5 font-semibold">${escapeHtml(f.title || 'N/A')}</p>
                    <p class="text-[10px] text-slate-500 mt-1 font-mono">${escapeHtml(f.description || '')}</p>
                    <p class="text-[9px] text-cyan-500/80 font-mono mt-2 uppercase tracking-wider font-semibold">▸ Click to expand remediation guide</p>
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

            const detailTr = document.createElement('tr');
            detailTr.id = `remediation-tr-${f.id}`;
            detailTr.className = 'remediation-details border-b border-slate-800/40 bg-[#060814]/60';
            
            const guide = getRemediation(f.title, f.description);
            const refLinks = (guide.references || []).map(link => `<a href="${link}" target="_blank" class="text-cyan-400 hover:underline mr-4 text-xs font-semibold font-mono">${escapeHtml(link)}</a>`).join('');

            detailTr.innerHTML = `
                <td colspan="4" class="p-6">
                    <div class="glass p-5 rounded-lg border border-slate-800/80 space-y-4">
                        <div>
                            <h4 class="text-xs font-bold text-rose-400 uppercase tracking-widest font-mono">// Security Impact</h4>
                            <p class="text-xs text-slate-300 mt-1">${escapeHtml(guide.impact)}</p>
                        </div>
                        <div>
                            <h4 class="text-xs font-bold text-cyan-400 uppercase tracking-widest font-mono">// Remediation Steps</h4>
                            <pre class="bg-[#02040a] p-4 rounded-lg border border-slate-900 text-xs font-mono text-emerald-400 whitespace-pre-wrap mt-1 leading-relaxed">${escapeHtml(guide.remediation)}</pre>
                        </div>
                        <div>
                            <h4 class="text-xs font-bold text-purple-400 uppercase tracking-widest font-mono">// References</h4>
                            <div class="mt-1 flex flex-wrap gap-2">${refLinks}</div>
                        </div>
                    </div>
                </td>
            `;

            tbody.appendChild(tr);
            tbody.appendChild(detailTr);
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

function openScanModal() {
    document.getElementById('scan-modal').classList.remove('hidden');
}

function closeScanModal() {
    document.getElementById('scan-modal').classList.add('hidden');
    document.getElementById('scan-target').value = '';
}

function dismissQuickStart() {
    document.getElementById('quick-start-banner').classList.add('hidden');
    try { localStorage.setItem('bbpts_quickstart_dismissed', '1'); } catch (e) {}
}

async function triggerActiveScan() {
    const target = document.getElementById('scan-target').value;
    const preset = document.getElementById('scan-preset').value;
    
    closeScanModal();
    showToast('Starting background scan task...', 'info');

    try {
        const response = await fetchAPI('/api/v2/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, preset })
        });
        const result = await response.json();
        if (response.ok) {
            showToast('Background scan launched for ' + target);
            refreshData();
        } else {
            showToast(result.error || 'Failed to start scan', 'error');
        }
    } catch (e) {
        showToast('Error launching scan: ' + e.message, 'error');
    }
}

function showToast(msg, type) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg text-xs font-mono font-bold shadow-xl transition-all duration-300 ' +
        (type === 'error' ? 'bg-rose-600 text-white' : type === 'info' ? 'bg-amber-600 text-white' : 'bg-cyan-600 text-white');
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

function showLoginOverlay() {
    document.getElementById('login-overlay').classList.remove('hidden');
}

function hideLoginOverlay() {
    document.getElementById('login-overlay').classList.add('hidden');
}

async function submitLogin() {
    const user = document.getElementById('login-username').value;
    const pass = document.getElementById('login-password').value;
    const errDiv = document.getElementById('login-error');
    errDiv.classList.add('hidden');

    try {
        const response = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        const result = await response.json();
        if (response.ok) {
            hideLoginOverlay();
            showToast('Authenticated successfully');
            refreshData();
        } else {
            errDiv.textContent = result.error || 'Authentication failed';
            errDiv.classList.remove('hidden');
        }
    } catch (e) {
        errDiv.textContent = 'Error: ' + e.message;
        errDiv.classList.remove('hidden');
    }
}
