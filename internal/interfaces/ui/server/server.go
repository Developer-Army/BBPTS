// Package server — server.go provides the entry point for starting the BBPTS
// web dashboard server.
package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// Config holds the web server configuration.
type Config struct {
	Port int
}

// Start launches the BBPTS dashboard server on the specified port.
func Start(cfg Config, db *storage.DB) error {
	api := NewAPI(db)

	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/stats", api.GetStats)
	mux.HandleFunc("/api/scans", api.GetScans)
	mux.HandleFunc("/api/events", api.GetEvents)

	// Static Frontend (Embedded or simply served from a string for now)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(DashboardHTML)); err != nil {
			slog.Warn("failed to write dashboard html", "error", err)
		}
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	slog.Info("dashboard server starting", "addr", "http://localhost"+addr)

	return http.ListenAndServe(addr, mux)
}

// DashboardHTML is the embedded frontend for the BBPTS elite dashboard.
const DashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BBPTS | Mission Control</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Outfit', sans-serif; background-color: #0b0e14; color: #f8fafc; margin: 0; overflow-x: hidden; }
        .glass { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); }
        .accent-purple { color: #bd93f9; }
        .bg-accent-purple { background-color: #bd93f9; }
        .glow-critical { box-shadow: 0 0 15px rgba(255, 85, 85, 0.3); border: 1px solid rgba(255, 85, 85, 0.5); }
        .glow-high { box-shadow: 0 0 15px rgba(255, 184, 108, 0.3); border: 1px solid rgba(255, 184, 108, 0.5); }
        .sidebar { width: 260px; border-right: 1px solid rgba(255, 255, 255, 0.05); }
        .nav-item { transition: all 0.2s; border-left: 3px solid transparent; }
        .nav-item:hover { background: rgba(189, 147, 249, 0.1); border-left-color: #bd93f9; }
        .nav-active { background: rgba(189, 147, 249, 0.15); border-left-color: #bd93f9; color: #bd93f9; }
    </style>
</head>
<body class="flex h-screen">
    <!-- Sidebar -->
    <aside class="sidebar glass flex flex-col p-6 shrink-0">
        <div class="mb-10 px-2">
            <h1 class="text-2xl font-bold tracking-tighter"><span class="accent-purple">BBPTS</span><span class="text-slate-500 font-light">.io</span></h1>
            <p class="text-[10px] text-slate-500 uppercase tracking-widest mt-1">Elite Recon Engine</p>
        </div>
        
        <nav class="flex-grow space-y-1">
            <a href="#" class="nav-item nav-active flex items-center gap-3 p-3 rounded-lg text-sm font-medium">
                <span>Dashboard</span>
            </a>
            <a href="#" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Targets</span>
            </a>
            <a href="#" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Scans</span>
            </a>
            <a href="#" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Vulnerabilities</span>
            </a>
        </nav>

        <div class="mt-auto pt-6 border-t border-slate-800/50">
            <div class="flex items-center gap-3 px-2">
                <div class="w-8 h-8 rounded-full bg-accent-purple/20 flex items-center justify-center text-accent-purple text-xs font-bold">DA</div>
                <div>
                    <p class="text-xs font-semibold">Dev Army</p>
                    <p class="text-[10px] text-slate-500">Security Operator</p>
                </div>
            </div>
        </div>
    </aside>

    <!-- Main Content -->
    <div class="flex-grow overflow-y-auto bg-[#0b0e14] relative">
        <header class="p-8 pb-4 flex justify-between items-start">
            <div>
                <h2 class="text-3xl font-semibold tracking-tight">Mission Control</h2>
                <p class="text-slate-400 text-sm mt-1">System operational. Monitoring attack surface telemetry.</p>
            </div>
            <div class="flex gap-3">
                <button class="bg-accent-purple text-slate-950 px-4 py-2 rounded-lg font-semibold text-sm hover:opacity-90 transition-opacity">Deploy Scanner</button>
            </div>
        </header>

        <main class="p-8 pt-4">
            <!-- Stats Grid -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="glass p-6 rounded-2xl relative overflow-hidden">
                    <h3 class="text-slate-400 text-[10px] uppercase tracking-widest font-bold mb-1">Total Targets</h3>
                    <p id="stat-targets" class="text-3xl font-bold">0</p>
                    <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-blue-500/10 rounded-full blur-xl"></div>
                </div>
                <div class="glass p-6 rounded-2xl relative overflow-hidden">
                    <h3 class="text-slate-400 text-[10px] uppercase tracking-widest font-bold mb-1">Active Scans</h3>
                    <p id="stat-scans" class="text-3xl font-bold">0</p>
                    <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-purple-500/10 rounded-full blur-xl"></div>
                </div>
                <div class="glass p-6 rounded-2xl relative overflow-hidden glow-critical">
                    <h3 class="text-rose-400 text-[10px] uppercase tracking-widest font-bold mb-1">Critical Vulns</h3>
                    <p id="stat-critical" class="text-3xl font-bold text-rose-500">0</p>
                    <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-rose-500/10 rounded-full blur-xl"></div>
                </div>
                <div class="glass p-6 rounded-2xl relative overflow-hidden">
                    <h3 class="text-emerald-400 text-[10px] uppercase tracking-widest font-bold mb-1">Fleet Health</h3>
                    <p class="text-3xl font-bold text-emerald-400">98%</p>
                    <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-emerald-500/10 rounded-full blur-xl"></div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Findings Table -->
                <div class="lg:col-span-2 glass p-6 rounded-2xl">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-lg font-semibold tracking-tight">High-Severity Intelligence</h3>
                        <button class="text-xs text-slate-400 hover:text-white underline uppercase tracking-widest">View All Findings</button>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead>
                                <tr class="text-slate-500 text-[10px] uppercase tracking-widest border-b border-slate-800/50">
                                    <th class="pb-4 font-medium">Target / Asset</th>
                                    <th class="pb-4 font-medium">Status</th>
                                    <th class="pb-4 font-medium">Priority</th>
                                    <th class="pb-4 font-medium">Time</th>
                                </tr>
                            </thead>
                            <tbody id="scan-history" class="divide-y divide-slate-800/50">
                                <!-- Data injected here -->
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Chart -->
                <div class="glass p-6 rounded-2xl">
                    <h3 class="text-lg font-semibold tracking-tight mb-6">Attack Surface</h3>
                    <div class="relative h-[250px] flex items-center justify-center">
                        <canvas id="surface-chart"></canvas>
                    </div>
                    <div class="mt-6 space-y-3">
                        <div class="flex justify-between text-xs">
                            <span class="text-slate-400">Subdomains</span>
                            <span class="font-bold">45%</span>
                        </div>
                        <div class="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                            <div class="bg-accent-purple h-full" style="width: 45%"></div>
                        </div>
                        <div class="flex justify-between text-xs">
                            <span class="text-slate-400">Public IPs</span>
                            <span class="font-bold">28%</span>
                        </div>
                        <div class="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                            <div class="bg-blue-400 h-full" style="width: 28%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        async function refreshData() {
            try {
                const [statsResp, scansResp] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/scans')
                ]);
                
                const stats = await statsResp.json();
                const scans = await scansResp.json();
                
                document.getElementById('stat-targets').innerText = stats.total_targets.toLocaleString();
                document.getElementById('stat-scans').innerText = stats.total_scans;
                document.getElementById('stat-critical').innerText = stats.critical_vulns;
                
                const tbody = document.getElementById('scan-history');
                tbody.innerHTML = scans.slice(0, 5).map(s => ` + "`" + `
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
                        <td class="py-4">
                            <span class="text-rose-500 text-xs font-bold">HIGH</span>
                        </td>
                        <td class="py-4 text-slate-400 text-[10px] uppercase">${new Date(s.start_time).toLocaleTimeString()}</td>
                    </tr>
                ` + "`" + `).join('');

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

        window.onload = refreshData;
        setInterval(refreshData, 10000);
    </script>
</body>
</html>
`
