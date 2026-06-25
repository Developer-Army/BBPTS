package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// generateHTMLReport exports report as HTML
func (rg *ReportGenerator) generateHTMLReport(report *Report) error {
	outputPath := filepath.Join(rg.config.OutputPath, "report.html")

	findingsHTML := rg.generateFindingsHTML(report.Findings)
	recsHTML := rg.generateRecommendationsHTML(report.Recommendations)

	// Attack Paths Graph generation
	type GraphNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Group string `json:"group"`
	}
	type GraphEdge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}

	graphNodes := make(map[string]GraphNode)
	var graphEdges []GraphEdge
	edgeMap := make(map[string]bool)

	for _, p := range report.AttackPaths {
		for i, nodeVal := range p.Path {
			group := "asset"
			if i == 0 {
				group = "origin"
			} else if i == len(p.Path)-1 {
				group = "vulnerability"
			}
			graphNodes[nodeVal] = GraphNode{ID: nodeVal, Label: nodeVal, Group: group}
			if i > 0 {
				prev := p.Path[i-1]
				key := prev + "->" + nodeVal
				if !edgeMap[key] {
					graphEdges = append(graphEdges, GraphEdge{From: prev, To: nodeVal})
					edgeMap[key] = true
				}
			}
		}
	}

	nodesList := []GraphNode{}
	for _, n := range graphNodes {
		nodesList = append(nodesList, n)
	}
	if len(graphEdges) == 0 {
		graphEdges = []GraphEdge{}
	}

	nodesJSON, _ := json.Marshal(nodesList)
	edgesJSON, _ := json.Marshal(graphEdges)

	targetsHTML := ""
	if len(report.TopTargets) > 0 {
		targetsHTML += `
<div class="chart-section" style="margin-bottom: 28px;">
  <h2>Top Investigation Targets (Sniper Scope)</h2>
  <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
    <thead>
      <tr style="border-bottom: 2px solid var(--border); text-align: left;">
        <th style="padding: 10px; font-weight: 700;">Target</th>
         <th style="padding: 10px; font-weight: 700;">Score</th>
        <th style="padding: 10px; font-weight: 700;">Why</th>
      </tr>
    </thead>
    <tbody>`
		for _, t := range report.TopTargets {
			whyBadges := ""
			for _, w := range t.Why {
				whyBadges += fmt.Sprintf(`<span class="tag" style="margin-right: 5px; background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.35);">%s</span>`, w)
			}
			targetsHTML += fmt.Sprintf(`
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 12px 10px; font-weight: 600;">%s</td>
        <td style="padding: 12px 10px;"><strong style="color: var(--high);">%.0f</strong></td>
        <td style="padding: 12px 10px;">%s</td>
      </tr>`, t.AssetID, t.FinalScore, whyBadges)
		}
		targetsHTML += `
    </tbody>
  </table>
</div>`
	}

	chainsHTML := ""
	if len(report.ChainedFindings) > 0 {
		chainsHTML += `
<div class="chart-section" style="margin-bottom: 28px;">
  <h2>Vulnerability Chains (Attack Paths)</h2>
  <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
    <thead>
      <tr style="border-bottom: 2px solid var(--border); text-align: left;">
        <th style="padding: 10px; font-weight: 700;">Target</th>
        <th style="padding: 10px; font-weight: 700;">Chain Type</th>
        <th style="padding: 10px; font-weight: 700;">CVSS</th>
        <th style="padding: 10px; font-weight: 700;">Details</th>
      </tr>
    </thead>
    <tbody>`
		for _, c := range report.ChainedFindings {
			chainsHTML += fmt.Sprintf(`
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 12px 10px; font-weight: 600;">%s</td>
        <td style="padding: 12px 10px; color: var(--critical); font-weight: bold;">%s</td>
        <td style="padding: 12px 10px;"><strong style="color: var(--critical);">%.1f</strong></td>
        <td style="padding: 12px 10px; font-size: 0.85rem; color: var(--muted);">%s (Chained: %s)</td>
      </tr>`, c.Target, c.ChainType, c.CombinedCVSS, c.Description, strings.Join(c.Findings, " + "))
		}
		chainsHTML += `
    </tbody>
  </table>
</div>`
	}

	pathsHTML := ""
	if len(report.AttackPaths) > 0 {
		pathsHTML += `
<div class="chart-section" style="margin-bottom: 28px;">
  <h2>Attack Paths Network Graph</h2>
  <div id="attack-path-network" style="width: 100%; height: 350px; background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; margin-top: 10px; position: relative;"></div>
</div>
<div class="chart-section" style="margin-bottom: 28px;">
  <h2>Top Attack Paths</h2>
  <ul style="list-style: none; display: flex; flex-direction: column; gap: 10px; margin-top: 10px;">`
		for _, p := range report.AttackPaths {
			pathsHTML += fmt.Sprintf(`
    <li style="background: var(--surface2); padding: 12px 16px; border-radius: 8px; border-left: 4px solid var(--primary); font-size: 0.9rem;">
      <strong style="color: var(--accent); margin-right: 10px;">Score: %.0f</strong> %s
    </li>`, p.Score, strings.Join(p.Path, " &rarr; "))
		}
		pathsHTML += `
  </ul>
</div>`
	}

	maxCount := report.CriticalCount
	if report.HighCount > maxCount {
		maxCount = report.HighCount
	}
	if report.MediumCount > maxCount {
		maxCount = report.MediumCount
	}
	if report.LowCount > maxCount {
		maxCount = report.LowCount
	}
	if maxCount == 0 {
		maxCount = 1
	}
	critW := report.CriticalCount * 100 / maxCount
	highW := report.HighCount * 100 / maxCount
	medW := report.MediumCount * 100 / maxCount
	lowW := report.LowCount * 100 / maxCount

	riskBadgeClass := "badge-low"
	switch report.Executive.OverallRisk {
	case "Critical":
		riskBadgeClass = "badge-critical"
	case "High":
		riskBadgeClass = "badge-high"
	case "Medium":
		riskBadgeClass = "badge-medium"
	}

	critLabel := ""
	if report.CriticalCount > 0 {
		critLabel = fmt.Sprintf("%d", report.CriticalCount)
	}
	highLabel := ""
	if report.HighCount > 0 {
		highLabel = fmt.Sprintf("%d", report.HighCount)
	}
	medLabel := ""
	if report.MediumCount > 0 {
		medLabel = fmt.Sprintf("%d", report.MediumCount)
	}
	lowLabel := ""
	if report.LowCount > 0 {
		lowLabel = fmt.Sprintf("%d", report.LowCount)
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BBPTS Recon Report</title>
<script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--border:#475569;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--primary:#3b82f6;--critical:#ef4444;--high:#fb923c;--medium:#eab308;--low:#22c55e}
body.light-theme {
  --bg:#f8fafc;
  --surface:#ffffff;
  --surface2:#f1f5f9;
  --border:#cbd5e1;
  --text:#0f172a;
  --muted:#64748b;
  --accent:#0284c7;
  --primary:#2563eb;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;font-size:15px;transition: background 0.3s, color 0.3s}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1140px;margin:0 auto;padding:32px 20px}
.header{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--border);border-radius:16px;padding:40px 48px;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px}
.header h1{font-size:1.9rem;font-weight:800;letter-spacing:-.03em;margin-bottom:6px}
.header p{color:var(--muted);font-size:.9rem}
.risk-badge{padding:10px 22px;border-radius:9999px;font-size:.8rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}
.badge-critical{background:rgba(239,68,68,.15);color:var(--critical);border:1px solid rgba(239,68,68,.35)}
.badge-high{background:rgba(251,146,60,.15);color:var(--high);border:1px solid rgba(251,146,60,.35)}
.badge-medium{background:rgba(251,191,36,.15);color:var(--medium);border:1px solid rgba(251,191,36,.35)}
.badge-low{background:rgba(52,211,153,.15);color:var(--low);border:1px solid rgba(52,211,153,.35)}

/* Controls styling */
.controls-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 20px;
  border-radius: 12px;
  margin-bottom: 28px;
  align-items: center;
}
.search-input {
  flex: 1;
  min-width: 200px;
  background: var(--surface2);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 10px 16px;
  border-radius: 8px;
  font-size: 0.9rem;
}
.search-input:focus {
  outline: none;
  border-color: var(--accent);
}
.filter-group {
  display: flex;
  align-items: center;
  gap: 8px;
}
.filter-label {
  font-size: 0.8rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--muted);
}
.btn {
  background: var(--surface2);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
  transition: 0.2s;
}
.btn:hover {
  background: var(--border);
}
.sev-checkboxes {
  display: flex;
  gap: 12px;
  font-size: 0.85rem;
}
.sev-checkboxes label {
  display: flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
}
.select-input {
  background: var(--surface2);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 0.85rem;
  outline: none;
}

.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}
.scard{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:.2s}
.scard:hover{border-color:var(--accent);transform:translateY(-2px)}
.scard .num{font-size:2.3rem;font-weight:800;margin-bottom:4px}
.scard .lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.scard.c .num{color:var(--critical)}.scard.h .num{color:var(--high)}.scard.m .num{color:var(--medium)}.scard.l .num{color:var(--low)}
.chart-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:26px 30px;margin-bottom:28px}
.chart-section h2{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.bar-label{font-size:.78rem;font-weight:700;text-transform:uppercase;width:60px;flex-shrink:0}
.bar-track{flex:1;background:var(--surface2);border-radius:6px;height:20px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;font-size:.72rem;font-weight:700;color:rgba(0,0,0,.75)}
.bar-count{font-size:.82rem;font-weight:700;width:30px;text-align:right;flex-shrink:0}
.guide{background:var(--surface2);border:1px dashed var(--primary);border-radius:14px;padding:26px 30px;margin-bottom:28px}
.guide h2{font-size:1rem;font-weight:800;color:var(--accent);margin-bottom:16px}
.guide-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.gstep{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative}
.gstep-num{position:absolute;top:-10px;left:-10px;width:24px;height:24px;background:var(--primary);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.78rem}
.gstep h3{font-size:.9rem;font-weight:700;margin:4px 0 6px}
.gstep p,.gstep li{font-size:.8rem;color:var(--muted)}
.gstep ul{padding-left:12px}
.gstep code{background:rgba(59,130,246,.15);color:#93c5fd;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.76rem}
.section-title{font-size:1.2rem;font-weight:800;margin-bottom:18px;padding-bottom:10px;border-bottom:2px solid var(--border)}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden;transition:.2s}
.finding:hover{box-shadow:0 12px 28px rgba(0,0,0,.3)}
.finding-head{padding:18px 22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;cursor:pointer;user-select:none}
.finding-host a{color:var(--text);font-size:1rem;font-weight:700}
.finding-host a:hover{color:var(--accent)}
.fmeta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev-badge{padding:4px 11px;border-radius:9999px;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em}
.score-pill{background:var(--surface2);border:1px solid var(--border);border-radius:9999px;padding:3px 11px;font-size:.76rem;color:var(--muted)}
.score-pill strong{color:var(--text)}
.toggle-icon{font-size:0.75rem;color:var(--muted);transition:.2s;margin-left:6px}
.finding-body{padding:0 22px 22px;display:none;border-top:1px solid var(--border)}
.finding-body.open{display:block}
.fsection{margin-top:18px}
.fsection-label{font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;color:var(--accent);margin-bottom:8px}
.reasons-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.reasons-list li{padding-left:16px;position:relative;font-size:.88rem;color:#cbd5e1}
.reasons-list li::before{content:">";position:absolute;left:0;color:var(--primary)}
.tag-list{display:flex;flex-wrap:wrap;gap:7px}
.tag{background:rgba(59,130,246,.1);color:#93c5fd;border:1px solid rgba(59,130,246,.2);border-radius:9999px;padding:2px 9px;font-size:.72rem;font-weight:600}
.evidence-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.evidence-list li{font-size:.8rem}
.evidence-list a{font-family:monospace;color:var(--accent);word-break:break-all}
.checklist{list-style:none;display:flex;flex-direction:column;gap:9px}
.checklist li label{display:flex;align-items:flex-start;gap:9px;cursor:pointer;font-size:.86rem;color:#cbd5e1}
.checklist li label:hover{color:var(--text)}
.checklist li input{width:1.05em;height:1.05em;accent-color:var(--primary);cursor:pointer;flex-shrink:0;margin-top:2px}
.checklist li input:checked+span{text-decoration:line-through;opacity:.45}
.next-action{border-left:4px solid var(--primary);background:rgba(59,130,246,.05);border-radius:0 8px 8px 0;padding:13px 16px;margin-top:16px;font-size:.86rem;color:#e2e8f0}
.next-action.sev-critical,.next-action.sev-high{border-left-color:var(--high)}
.next-action.sev-medium{border-left-color:var(--medium)}
.next-action.sev-low{border-left-color:var(--low)}
.sources-row{font-size:.8rem;color:var(--muted);margin-top:10px}
.recs{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:26px 30px;margin-bottom:28px}
.recs ol{padding-left:20px;color:#cbd5e1}
.recs ol li{margin-bottom:9px;font-size:.9rem}
.empty-state{text-align:center;padding:60px;color:var(--muted);background:var(--surface);border:1px dashed var(--border);border-radius:12px}
footer{text-align:center;padding:36px 0 16px;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);margin-top:16px}
.suppressed-finding {
  background: #1e293b !important;
  opacity: 0.65;
  border-color: #475569 !important;
  filter: grayscale(80%);
}
body.light-theme .suppressed-finding {
  background: #f1f5f9 !important;
  border-color: #cbd5e1 !important;
}
</style>
</head>
<body>
<div class="wrap">

<header class="header">
  <div>
    <h1>BBPTS Recon Report</h1>
    <p>Generated ` + report.GeneratedAt.Format("2006-01-02 15:04 UTC") + ` &nbsp;·&nbsp; ` + fmt.Sprintf("%d targets", report.TargetCount) + `</p>
  </div>
  <div style="display:flex;align-items:center;gap:12px;">
    <button onclick="toggleTheme()" class="btn" style="border-radius:20px;">🌗 Theme</button>
    <span class="risk-badge ` + riskBadgeClass + `">Overall Risk: ` + report.Executive.OverallRisk + `</span>
  </div>
</header>

<div class="summary-grid">
  <div class="scard"><div class="num">` + fmt.Sprintf("%d", report.TargetCount) + `</div><div class="lbl">Targets</div></div>
  <div class="scard c"><div class="num">` + fmt.Sprintf("%d", report.CriticalCount) + `</div><div class="lbl">Critical</div></div>
  <div class="scard h"><div class="num">` + fmt.Sprintf("%d", report.HighCount) + `</div><div class="lbl">High</div></div>
  <div class="scard m"><div class="num">` + fmt.Sprintf("%d", report.MediumCount) + `</div><div class="lbl">Medium</div></div>
  <div class="scard l"><div class="num">` + fmt.Sprintf("%d", report.LowCount) + `</div><div class="lbl">Low</div></div>
  <div class="scard"><div class="num">` + fmt.Sprintf("%d", report.FindingCount) + `</div><div class="lbl">Total</div></div>
</div>

<!-- Search & Filtering Controls -->
<div class="controls-bar">
  <input type="text" id="global-search" placeholder="Search targets, tags, findings..." oninput="filterFindings()" class="search-input">
  
  <div class="filter-group">
    <span class="filter-label">Severity</span>
    <div class="sev-checkboxes">
      <label><input type="checkbox" value="critical" class="sev-checkbox" onchange="filterFindings()"> Critical</label>
      <label><input type="checkbox" value="high" class="sev-checkbox" onchange="filterFindings()"> High</label>
      <label><input type="checkbox" value="medium" class="sev-checkbox" onchange="filterFindings()"> Medium</label>
      <label><input type="checkbox" value="low" class="sev-checkbox" onchange="filterFindings()"> Low</label>
    </div>
  </div>

  <div class="filter-group">
    <span class="filter-label">Tag</span>
    <select id="tag-filter" onchange="filterFindings()" class="select-input">
      <option value="all">All Tags</option>
      <!-- Tags populated dynamically -->
    </select>
  </div>

  <div style="margin-left:auto; display:flex; gap:8px;">
    <button onclick="expandAll()" class="btn">Expand All</button>
    <button onclick="collapseAll()" class="btn">Collapse All</button>
  </div>
</div>

<div class="chart-section">
  <h2>Severity Breakdown</h2>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--critical)">Critical</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", critW) + `%;background:var(--critical)">` + critLabel + `</div></div>
    <div class="bar-count" style="color:var(--critical)">` + fmt.Sprintf("%d", report.CriticalCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--high)">High</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", highW) + `%;background:var(--high)">` + highLabel + `</div></div>
    <div class="bar-count" style="color:var(--high)">` + fmt.Sprintf("%d", report.HighCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--medium)">Medium</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", medW) + `%;background:var(--medium)">` + medLabel + `</div></div>
    <div class="bar-count" style="color:var(--medium)">` + fmt.Sprintf("%d", report.MediumCount) + `</div>
  </div>
  <div class="bar-row">
    <div class="bar-label" style="color:var(--low)">Low</div>
    <div class="bar-track"><div class="bar-fill" style="width:` + fmt.Sprintf("%d", lowW) + `%;background:var(--low)">` + lowLabel + `</div></div>
    <div class="bar-count" style="color:var(--low)">` + fmt.Sprintf("%d", report.LowCount) + `</div>
  </div>
</div>

<div class="guide">
  <h2>What To Do With This Report</h2>
  <div class="guide-grid">
    <div class="gstep"><div class="gstep-num">1</div><h3>Import Into Proxy</h3><ul><li><strong>Burp:</strong> Project &rarr; Import scan items &rarr; <code>burp-import.xml</code></li><li><strong>Caido:</strong> Workspaces &rarr; Import &rarr; <code>caido-import.json</code></li><li><strong>ZAP:</strong> Import <code>zap-import.xml</code></li></ul></div>
    <div class="gstep"><div class="gstep-num">2</div><h3>Understand the Score</h3><p>Each finding has a Risk Score (0&ndash;100). Higher = more attack surface signals. Start with anything above 70.</p></div>
    <div class="gstep"><div class="gstep-num">3</div><h3>Expand a Finding</h3><p>Click any card below to expand it. You&rsquo;ll see exactly <em>why</em> it scored high and what to test.</p></div>
    <div class="gstep"><div class="gstep-num">4</div><h3>Work the Checklist</h3><p>Each finding has checkboxes. Tick off tests as you go. Critical/High first. Look for parameterized URLs &mdash; main attack surface.</p></div>
</div>

` + targetsHTML + chainsHTML + pathsHTML + `

<div class="section-title">Detailed Findings</div>
<div style="background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 20px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; font-size: 0.9rem; color: var(--muted);">
  <div><strong>Noise Filter Status:</strong> Total Evaluated: <span style="color: var(--text);">` + fmt.Sprintf("%d", report.ConfidenceSummary.TotalEvaluated) + `</span> &nbsp;|&nbsp; Kept: <span style="color: var(--low);">` + fmt.Sprintf("%d", report.ConfidenceSummary.KeptCount) + `</span> &nbsp;|&nbsp; Suppressed: <span style="color: var(--high);">` + fmt.Sprintf("%d", report.ConfidenceSummary.SuppressedCount) + `</span></div>
  <div><strong>Noise Reduction:</strong> <span style="color: var(--accent); font-weight: bold;">` + fmt.Sprintf("%.1f%%", report.ConfidenceSummary.NoiseReduction) + `</span></div>
</div>
<div id="findings-container">
` + findingsHTML + `
</div>

<div class="recs">
  <div class="section-title">Recommendations</div>
  <ol>` + recsHTML + `</ol>
</div>

<footer>BBPTS &mdash; Bug Bounty Pipeline &amp; Tracking System</footer>
</div>
<script>
// Collapsible headers
document.querySelectorAll('.finding-head').forEach(function(h){
  h.addEventListener('click',function(){
    var b=h.nextElementSibling,i=h.querySelector('.toggle-icon');
    if(b){b.classList.toggle('open');if(i)i.textContent=b.classList.contains('open')?'▲':'▼'}
  });
});

// Expand / Collapse all
function expandAll() {
  document.querySelectorAll('.finding-body').forEach(b => b.classList.add('open'));
  document.querySelectorAll('.toggle-icon').forEach(i => i.textContent = '▲');
}
function collapseAll() {
  document.querySelectorAll('.finding-body').forEach(b => b.classList.remove('open'));
  document.querySelectorAll('.toggle-icon').forEach(i => i.textContent = '▼');
}

// Dynamic tag list population
const allTags = new Set();
document.querySelectorAll('.tag').forEach(t => allTags.add(t.textContent.trim()));
const tagFilterSelect = document.getElementById('tag-filter');
allTags.forEach(tag => {
  const opt = document.createElement('option');
  opt.value = tag;
  opt.textContent = tag;
  tagFilterSelect.appendChild(opt);
});

// Theme management
function toggleTheme() {
  document.body.classList.toggle('light-theme');
  const isLight = document.body.classList.contains('light-theme');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
}
if (localStorage.getItem('theme') === 'light') {
  document.body.classList.add('light-theme');
}

// Global filter logic
function filterFindings() {
  const query = document.getElementById('global-search').value.toLowerCase();
  const sevFilter = Array.from(document.querySelectorAll('.sev-checkbox:checked')).map(cb => cb.value);
  const tagFilter = document.getElementById('tag-filter').value;

  document.querySelectorAll('.finding').forEach(card => {
    const text = card.textContent.toLowerCase();
    const matchesSearch = text.includes(query);

    let matchesSev = true;
    if (sevFilter.length > 0) {
      matchesSev = false;
      sevFilter.forEach(s => {
        if (card.classList.contains('sev-' + s)) matchesSev = true;
      });
    }

    let matchesTag = true;
    if (tagFilter !== 'all') {
      matchesTag = false;
      card.querySelectorAll('.tag').forEach(tagSpan => {
        if (tagSpan.textContent.trim() === tagFilter) matchesTag = true;
      });
    }

    if (matchesSearch && matchesSev && matchesTag) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

// Auto-expand high/critical findings initially
var exp=0;
document.querySelectorAll('.finding').forEach(function(card){
  if(exp>=3)return;
  var badge=card.querySelector('.sev-badge');
  if(badge&&/critical|high/i.test(badge.textContent)){
    var b=card.querySelector('.finding-body'),i=card.querySelector('.toggle-icon');
    if(b){b.classList.add('open');exp++;}
    if(i)i.textContent='▲';
  }
});

// Attack Paths Graph initialization
const graphNodes = ` + string(nodesJSON) + `;
const graphEdges = ` + string(edgesJSON) + `;
const netContainer = document.getElementById('attack-path-network');
if (netContainer && graphNodes && graphNodes.length > 0) {
  const data = {
    nodes: new vis.DataSet(graphNodes),
    edges: new vis.DataSet(graphEdges)
  };
  const options = {
    nodes: {
      shape: 'dot',
      size: 10,
      font: { size: 10, color: '#f8fafc' },
      borderWidth: 1.5
    },
    edges: {
      arrows: { to: { enabled: true, scaleFactor: 0.6 } },
      color: { color: '#475569', highlight: '#3b82f6' }
    },
    groups: {
      origin: { color: { background: '#22c55e', border: '#15803d' } },
      vulnerability: { color: { background: '#ef4444', border: '#b91c1c' } },
      asset: { color: { background: '#3b82f6', border: '#1d4ed8' } }
    },
    physics: {
      forceAtlas2Based: {
        gravitationalConstant: -26,
        centralGravity: 0.005,
        springLength: 150,
        springConstant: 0.18
      },
      maxVelocity: 50,
      solver: 'forceAtlas2Based',
      timestep: 0.35,
      stabilization: { iterations: 100 }
    }
  };
  new vis.Network(netContainer, data, options);
}
</script>
</body>
</html>`

	return os.WriteFile(outputPath, []byte(html), 0644)
}

// generateRecommendationsHTML formatting helper
func (rg *ReportGenerator) generateRecommendationsHTML(recs []string) string {
	var sb strings.Builder
	for _, rec := range recs {
		sb.WriteString(fmt.Sprintf("<li>%s</li>", rec))
	}
	return sb.String()
}

// generateFindingsHTML renders individual finding cards.
func (rg *ReportGenerator) generateFindingsHTML(findings []DetailedFinding) string {
	if len(findings) == 0 {
		return `<div class="empty-state">No findings above the minimum score threshold.</div>`
	}
	var sb strings.Builder
	for idx, f := range findings {
		sev := strings.ToLower(f.Severity)
		if sev == "" {
			sev = "info"
		}
		color := severityColor(sev)
		targetURL := makeURL(f.Target)
		cbPrefix := fmt.Sprintf("f%d", idx)

		extraClass := ""
		if f.Suppressed {
			extraClass = " suppressed-finding"
		}
		sb.WriteString(fmt.Sprintf(`<div class="finding sev-%s%s">`, sev, extraClass))
		sb.WriteString(`<div class="finding-head">`)
		sb.WriteString(fmt.Sprintf(`<div class="finding-host"><a href="%s" target="_blank" rel="noopener">%s</a></div>`, targetURL, f.Target))
		sb.WriteString(`<div class="fmeta">`)
		if f.Suppressed {
			sb.WriteString(`<span class="sev-badge" style="background:rgba(148,163,184,.15);color:#94a3b8;border:1px solid rgba(148,163,184,.3)">⚠ FP Risk: high</span>`)
		}
		sb.WriteString(fmt.Sprintf(`<span class="sev-badge" style="background:rgba(%s,.12);color:%s;border:1px solid rgba(%s,.3)">%s</span>`,
			hexToRGBComponents(color), color, hexToRGBComponents(color), strings.ToUpper(sev)))
		sb.WriteString(fmt.Sprintf(`<span class="score-pill">Score <strong>%d</strong>/100</span>`, f.Score))
		sb.WriteString(`<span class="toggle-icon">v</span>`)
		sb.WriteString(`</div></div>`)

		sb.WriteString(`<div class="finding-body">`)

		if f.ExposureScore > 0 || f.AttackabilityScore > 0 || f.BusinessImpactScore > 0 || f.ConfidenceScore > 0 || f.PathScore > 0 {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">Risk Vectors Breakdown</div><div class="risk-breakdown" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:8px;margin-bottom:12px;">`)
			sb.WriteString(fmt.Sprintf(`<div style="background:var(--surface2);padding:8px 12px;border-radius:6px;font-size:0.8rem;"><span style="color:var(--muted);display:block;">Exposure</span><strong>%d/100</strong></div>`, f.ExposureScore))
			sb.WriteString(fmt.Sprintf(`<div style="background:var(--surface2);padding:8px 12px;border-radius:6px;font-size:0.8rem;"><span style="color:var(--muted);display:block;">Attackability</span><strong>%d/100</strong></div>`, f.AttackabilityScore))
			sb.WriteString(fmt.Sprintf(`<div style="background:var(--surface2);padding:8px 12px;border-radius:6px;font-size:0.8rem;"><span style="color:var(--muted);display:block;">Business Impact</span><strong>%d/100</strong></div>`, f.BusinessImpactScore))
			sb.WriteString(fmt.Sprintf(`<div style="background:var(--surface2);padding:8px 12px;border-radius:6px;font-size:0.8rem;"><span style="color:var(--muted);display:block;">Confidence</span><strong>%d/100</strong></div>`, f.ConfidenceScore))
			sb.WriteString(fmt.Sprintf(`<div style="background:var(--surface2);padding:8px 12px;border-radius:6px;font-size:0.8rem;"><span style="color:var(--muted);display:block;">Path Score</span><strong>%d/100</strong></div>`, f.PathScore))
			sb.WriteString(`</div></div>`)
		}

		reasons := filterEmpty(strings.Split(f.Description, "; "))
		if len(reasons) > 0 {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">Why This Scored High</div><ul class="reasons-list">`)
			for _, r := range reasons {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, r))
			}
			sb.WriteString(`</ul></div>`)
		}

		if len(f.Tags) > 0 {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">Attack Surface Tags</div><div class="tag-list">`)
			for _, tag := range f.Tags {
				sb.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, tag))
			}
			sb.WriteString(`</div></div>`)
		}

		if f.Evidence != "" {
			parts := strings.Split(f.Evidence, " | ")
			var urls []string
			discoveredBy := ""
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Discovered by:") {
					discoveredBy = p
				} else if p != "" {
					urls = append(urls, p)
				}
			}
			if len(urls) > 0 || discoveredBy != "" {
				sb.WriteString(`<div class="fsection"><div class="fsection-label">Discovered URLs</div>`)
				if discoveredBy != "" {
					sb.WriteString(fmt.Sprintf(`<div class="sources-row">%s</div>`, discoveredBy))
				}
				if len(urls) > 0 {
					shown := urls
					extra := 0
					if len(shown) > 20 {
						extra = len(shown) - 20
						shown = shown[:20]
					}
					sb.WriteString(`<ul class="evidence-list">`)
					for _, u := range shown {
						sb.WriteString(fmt.Sprintf(`<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, makeURL(u), u))
					}
					if extra > 0 {
						sb.WriteString(fmt.Sprintf(`<li style="color:var(--muted)">... and %d more (see JSON report for full list)</li>`, extra))
					}
					sb.WriteString(`</ul>`)
				}
				sb.WriteString(`</div>`)
			}
		}

		if f.ScreenshotPath != "" {
			sb.WriteString(fmt.Sprintf(`<div class="fsection"><div class="fsection-label">Page Screenshot</div><div class="screenshot-container" style="margin-top:8px;"><a href="%s" target="_blank"><img src="%s" alt="Screenshot" style="max-width:240px;border:1px solid var(--border);border-radius:6px;cursor:pointer;box-shadow:0 4px 6px rgba(0,0,0,0.1);transition:transform 0.2s;" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'"></a></div></div>`, f.ScreenshotPath, f.ScreenshotPath))
		}

		if f.Remediation != "" {
			sb.WriteString(`<div class="fsection"><div class="fsection-label">Testing Checklist</div><ul class="checklist">`)
			if strings.HasPrefix(f.Remediation, "Suggested security tests: ") {
				tests := strings.TrimPrefix(f.Remediation, "Suggested security tests: ")
				for i, test := range strings.Split(tests, "\x00") {
					test = strings.TrimSpace(test)
					if test == "" {
						continue
					}
					cbID := fmt.Sprintf("%s-cb%d", cbPrefix, i)
					sb.WriteString(fmt.Sprintf(`<li><label for="%s"><input type="checkbox" id="%s"><span>%s</span></label></li>`, cbID, cbID, test))
				}
			} else {
				sb.WriteString(fmt.Sprintf(`<li><label><input type="checkbox"><span>%s</span></label></li>`, f.Remediation))
			}
			sb.WriteString(`</ul></div>`)
		}

		sb.WriteString(fmt.Sprintf(`<div class="next-action sev-%s">`, sev))
		switch sev {
		case "critical", "high":
			sb.WriteString(`<strong>Next Action:</strong> High-value target. Enable your proxy (Burp/Caido), open the target link, and run through the checklist. Focus on parameterized URLs — send to Repeater and try SQLi, SSRF, IDOR payloads. Any /admin or /api paths get tested for auth bypass.`)
		case "medium":
			sb.WriteString(`<strong>Next Action:</strong> Interesting target. Check if you can access it unauthenticated. Look for IDOR on numeric IDs in the path. Test CORS headers on API endpoints. Try parameter pollution.`)
		default:
			sb.WriteString(`<strong>Next Action:</strong> Recon data. Verify security headers (CSP, HSTS, X-Frame-Options). Check for exposed directory listings or subdomain takeover opportunities. Look for technology version disclosure.`)
		}
		sb.WriteString(`</div>`)

		if len(f.Sources) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="sources-row">Tools: %s</div>`, strings.Join(f.Sources, ", ")))
		}

		sb.WriteString(`</div></div>`)
	}
	return sb.String()
}

// generateAttackSurfaceGraph exports an interactive vis.js graph of the discovered assets
func (rg *ReportGenerator) generateAttackSurfaceGraph(events []recon.Event) error {
	outputPath := filepath.Join(rg.config.OutputPath, "attack_surface_graph.html")

	type Node struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Group string `json:"group"`
	}

	type Edge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}

	nodeMap := make(map[string]Node)
	var edges []Edge

	// Helper to extract base domain
	getBaseDomain := func(urlStr string) string {
		trimmed := strings.TrimPrefix(urlStr, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 {
			host := strings.Split(parts[0], ":")[0]
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				return parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
			return host
		}
		return ""
	}

	for _, ev := range events {
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}

		baseDomain := getBaseDomain(target)
		if baseDomain != "" && baseDomain != target {
			nodeMap[baseDomain] = Node{ID: baseDomain, Label: baseDomain, Group: "domain"}
		}

		if strings.HasPrefix(target, "http") {
			// Extract host
			trimmed := strings.TrimPrefix(target, "http://")
			trimmed = strings.TrimPrefix(trimmed, "https://")
			host := strings.Split(trimmed, "/")[0]

			nodeMap[host] = Node{ID: host, Label: host, Group: "subdomain"}
			nodeMap[target] = Node{ID: target, Label: target, Group: "url"}

			if baseDomain != "" && host != baseDomain {
				edges = append(edges, Edge{From: baseDomain, To: host})
			}
			edges = append(edges, Edge{From: host, To: target})
		} else {
			nodeMap[target] = Node{ID: target, Label: target, Group: "asset"}
			if baseDomain != "" {
				edges = append(edges, Edge{From: baseDomain, To: target})
			}
		}
	}

	var nodes []Node
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}

	nodesJSON, _ := json.Marshal(nodes)
	edgesJSON, _ := json.Marshal(edges)

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>BBPTS Attack Surface Graph</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body, html { margin: 0; padding: 0; width: 100%%; height: 100%%; background-color: #0f172a; color: white; font-family: sans-serif; }
        #mynetwork { width: 100%%; height: 100%%; border: none; }
        .header { position: absolute; top: 20px; left: 20px; z-index: 100; pointer-events: none; }
        h1 { margin: 0; font-size: 24px; color: #38bdf8; }
        p { margin: 5px 0 0 0; color: #94a3b8; }
    </style>
</head>
<body>
<div class="header">
    <h1>Attack Surface Graph</h1>
    <p>Interactive visualization of discovered assets</p>
</div>
<div id="mynetwork"></div>
<script type="text/javascript">
    var nodes = new vis.DataSet(%s);
    var edges = new vis.DataSet(%s);

    var container = document.getElementById('mynetwork');
    var data = { nodes: nodes, edges: edges };
    var options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#e2e8f0', size: 14 }
        },
        edges: {
            color: '#475569',
            smooth: { type: 'continuous' }
        },
        groups: {
            domain: { color: { background: '#ef4444', border: '#b91c1c' }, size: 24 },
            subdomain: { color: { background: '#f59e0b', border: '#b45309' }, size: 20 },
            url: { color: { background: '#10b981', border: '#047857' }, size: 12 },
            asset: { color: { background: '#6366f1', border: '#4338ca' }, size: 16 }
        },
        physics: {
            forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 },
            maxVelocity: 50,
            solver: 'forceAtlas2Based',
            timestep: 0.35,
            stabilization: { iterations: 150 }
        }
    };
    var network = new vis.Network(container, data, options);
</script>
</body>
</html>`, string(nodesJSON), string(edgesJSON))

	return os.WriteFile(outputPath, []byte(htmlContent), 0644)
}

// hexToRGBComponents converts a #RRGGBB hex color to "R,G,B" for use in rgba().
func hexToRGBComponents(hex string) string {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return "148,163,184"
	}
	var r, g, b uint8
	if _, err := fmt.Sscanf(hex[:2], "%02x", &r); err != nil {
		return "148,163,184"
	}
	if _, err := fmt.Sscanf(hex[2:4], "%02x", &g); err != nil {
		return "148,163,184"
	}
	if _, err := fmt.Sscanf(hex[4:6], "%02x", &b); err != nil {
		return "148,163,184"
	}
	return fmt.Sprintf("%d,%d,%d", r, g, b)
}

// severityColor returns a CSS hex color for the given severity label.
func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "#ef4444"
	case "high":
		return "#fb923c"
	case "medium":
		return "#fbbf24"
	case "low":
		return "#34d399"
	default:
		return "#94a3b8"
	}
}
