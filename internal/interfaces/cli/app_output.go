package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/baseline"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/triage"
	"github.com/Developer-Army/BBPTS/internal/domain/ownership"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	ui "github.com/Developer-Army/BBPTS/internal/interfaces/ui/report"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/quota"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

func handleIntelligence(ctx context.Context, opts Options, cfg *config.Config, store *storage.Storage, events []recon.Event, matches []recon.Match, triggeredTools []string, threads int, bridge *tui.Bridge) []recon.Event {
	_ = matches
	_ = bridge
	slog.Info("Running Advanced Offensive Intelligence Engine")

	te := triage.NewTriageEngine()
	scorer := recon.NewScorer()

	// Convert events to findings
	findings := make([]*triage.Finding, len(events))
	for i, ev := range events {
		findings[i] = &triage.Finding{
			Type:   ev.Type,
			Target: ev.Target,
			Source: ev.Source,
		}
	}

	// Filter noise and prioritize
	actionable := te.FilterNoise(findings)
	prioritized := te.PrioritizeFindings(actionable)

	// Keep a map from type:target to original event to preserve original properties
	eventMap := make(map[string]recon.Event)
	for _, ev := range events {
		key := fmt.Sprintf("%s:%s", ev.Type, ev.Target)
		eventMap[key] = ev
	}

	// Convert back to events, scoring HTTP endpoints along the way
	triagedEvents := make([]recon.Event, 0, len(prioritized))
	for _, f := range prioritized {
		key := fmt.Sprintf("%s:%s", f.Type, f.Target)
		ev, ok := eventMap[key]
		if !ok {
			ev = recon.Event{
				Type:   f.Type,
				Target: f.Target,
				Source: f.Source,
			}
		}

		if strings.HasPrefix(ev.Target, "http") {
			var hasOwner, hasAttackPath bool
			var evidenceCount int
			var exploitability int
			var isAuthRequired bool

			if ev.Properties != nil {
				if val, ok := ev.Properties["auth_required"]; ok && val == "true" {
					isAuthRequired = true
				} else if val, ok := ev.Properties["authenticated"]; ok && val == "true" {
					isAuthRequired = true
				}
			}

			if store != nil {
				if asset, err := store.GetAsset(ev.Target); err == nil && asset != nil {
					ao := &ownership.AssetOwnership{
						AssetID: asset.ID,
					}
					if asset.OwnerID != nil {
						ao.OwnerID = *asset.OwnerID
						ao.Confidence = asset.Confidence
					}
					hasOwner = !ao.IsUnmanagedRisk()
				}

				if evs, err := store.GetEvidenceByAssetID(ev.Target); err == nil {
					evidenceCount = len(evs)
				}

				if db := store.GetDB(); db != nil {
					var count int
					nodeID := storage.GenerateNodeID("domain", ev.Target, "")
					err := db.QueryRow("SELECT COUNT(*) FROM asset_edges WHERE target_id = ? OR target_id = ?", ev.Target, nodeID).Scan(&count)
					if err == nil && count > 0 {
						hasAttackPath = true
					}
				}
			}

			score := scorer.ScoreEndpointAdvanced(ev.Target, isAuthRequired, "", hasOwner, hasAttackPath, evidenceCount, exploitability)
			if store != nil {
				if history, err := store.GetFindingHistory(ctx, ev.Target, 50, 0); err == nil {
					scorer.AdjustScoreWithHistory(score, len(history))
				}
			}
			if score.Score > 0 {
				slog.Info("High Value Target Prioritized", "target", ev.Target, "severity", score.Severity, "score", score.Score, "reasons", score.Justification)
				if ev.Properties == nil {
					ev.Properties = make(map[string]string)
				}
				ev.Properties["scorer_score"] = fmt.Sprintf("%d", score.Score)
				ev.Properties["scorer_severity"] = score.Severity
				ev.Properties["scorer_justification"] = strings.Join(score.Justification, ", ")
				ev.Properties["scorer_exposure"] = fmt.Sprintf("%d", score.ExposureScore)
				ev.Properties["scorer_attackability"] = fmt.Sprintf("%d", score.AttackabilityScore)
				ev.Properties["scorer_business_impact"] = fmt.Sprintf("%d", score.BusinessImpactScore)
				ev.Properties["scorer_confidence"] = fmt.Sprintf("%d", score.ConfidenceScore)
				ev.Properties["scorer_freshness"] = fmt.Sprintf("%d", score.FreshnessScore)
				ev.Properties["scorer_path_score"] = fmt.Sprintf("%d", score.PathScore)
				if vectorJSON, err := json.Marshal(score.Risk); err == nil {
					ev.Properties["scorer_risk_vector"] = string(vectorJSON)
				}
			}
		}
		triagedEvents = append(triagedEvents, ev)
	}

	if len(triggeredTools) > 0 {
		if opts.PassiveMode {
			var passiveTriggered []string
			activeBlacklist := map[string]bool{
				"naabu":       true,
				"nuclei":      true,
				"dalfox":      true,
				"ffuf":        true,
				"gobuster":    true,
				"feroxbuster": true,
				"katana":      true,
			}
			for _, t := range triggeredTools {
				tLower := strings.TrimSpace(strings.ToLower(t))
				if !activeBlacklist[tLower] {
					passiveTriggered = append(passiveTriggered, t)
				}
			}
			slog.Info("Passive mode active: filtered triggered tools", "before", triggeredTools, "after", passiveTriggered)
			triggeredTools = passiveTriggered
		}
	}

	if len(triggeredTools) > 0 {
		if !opts.ExploitSQLI {
			triggeredTools = FilterExcludedTools(triggeredTools, "sqlmap")
		}
	}

	if len(triggeredTools) > 0 {
		slog.Info("recon triggered additional tools", "count", len(triggeredTools), "tools", triggeredTools)
		// Extract targets from triagedEvents
		var triagedTargets []string
		seenTargets := make(map[string]struct{})
		for _, ev := range triagedEvents {
			if _, ok := seenTargets[ev.Target]; !ok {
				seenTargets[ev.Target] = struct{}{}
				triagedTargets = append(triagedTargets, ev.Target)
			}
		}

		if len(triagedTargets) > 0 {
			reconConfig := services.Config{
				ToolNames:     triggeredTools,
				Threads:       threads,
				RateLimit:     opts.RateLimit,
				Proxies:       cfg.Proxies,
				APIKeys:       cfg.APIKeys,
				WordlistsDir:  cfg.WordlistsDir,
				ContainerMode: cfg.ContainerMode,
				DockerImages:  cfg.DockerImages,
				ExploitSQLI:   opts.ExploitSQLI,
				ForceHTTP1:    opts.ForceHTTP1,
			}
			orchestrator := services.NewOrchestrator(reconConfig)
			if orchestrator != nil {
				defer orchestrator.Close()
				slog.Info("Running triggered tools on triaged targets...", "tools", triggeredTools, "targets", len(triagedTargets))
				triggeredEvents, err := orchestrator.Run(ctx, triagedTargets)
				if err != nil {
					slog.Warn("triggered tools run failed", "error", err)
				} else if len(triggeredEvents) > 0 {
					slog.Info("triggered tools completed successfully", "new_events", len(triggeredEvents))
					triagedEvents = append(triagedEvents, convertServicesEventsToRecon(triggeredEvents)...)
				}
			}
		}
	}

	return triagedEvents
}

func handleReporting(ctx context.Context, opts Options, cfg *config.Config, store *storage.Storage, normalized []string, events []recon.Event, matches []recon.Match, bridge *tui.Bridge) {
	// Wire BaselineStore for continuous monitoring
	scope := opts.Scope
	if scope == "" {
		scope = "default_run"
	}
	newCount := 0
	if bs, err := baseline.NewBaselineStore(cfg.StateDir, scope); err == nil {
		for _, ev := range events {
			isNew, _, _ := bs.AddFinding(ev.Source, ev.Type, ev.Target)
			if isNew {
				newCount++
			}
		}
		slog.Info("Baseline analysis complete", "total_events", len(events), "new_events", newCount)
		_ = bs.SaveSessionDiff()
		_ = bs.Close()
	} else {
		slog.Warn("Failed to initialize baseline store", "error", err)
	}

	insights := analyze.DeriveInsights(normalized, events)

	// Inject rule tags into insights
	blockedHosts := make(map[string]bool)
	for _, match := range matches {
		for i := range insights {
			if insights[i].Host == match.Event.Target || strings.Contains(match.Event.Target, insights[i].Host) {
				switch match.Rule.Action.Type {
				case "tag":
					insights[i].Tags = append(insights[i].Tags, match.Rule.Action.Tag)
					insights[i].Reasons = append(insights[i].Reasons, match.Rule.Description)
					insights[i].Score += 10 // Bonus for rule matches
				case "block":
					blockedHosts[insights[i].Host] = true
				case "elevate":
					insights[i].Priority = "critical"
					insights[i].Score = 100 // Bumps score to max
					insights[i].Reasons = append(insights[i].Reasons, "Elevated by triage rule: "+match.Rule.Description)
				}
			}
		}
	}

	if len(blockedHosts) > 0 {
		var filtered []analyze.Insight
		for _, in := range insights {
			if !blockedHosts[in.Host] {
				filtered = append(filtered, in)
			}
		}
		insights = filtered
	}

	if opts.JSONOutput {
		data, err := json.MarshalIndent(insights, "", "  ")
		if err != nil {
			slog.Error("failed to serialize insights to JSON", "error", err)
		} else {
			fmt.Println(string(data))
		}
	}

	if bridge != nil {
		for _, in := range insights {
			bridge.SendInsight(in.Host, in.Priority, in.Score)
		}
	}

	// Dispatch real-time alerts for high-priority findings
	if cfg.Notify.DiscordWebhook != "" || cfg.Notify.SlackWebhook != "" || (cfg.Notify.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "") {
		notifier := utils.NewNotifier(utils.Config(notifierConfigFrom(cfg.Notify)))
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				f := utils.Finding{
					Host:     in.Host,
					Priority: in.Priority,
					Score:    in.Score,
					Tags:     in.Tags,
					Reasons:  in.Reasons,
				}
				if hasBeenReported(cfg.StateDir, f) {
					slog.Debug("Skipping duplicate alert (already reported)", "host", in.Host)
					continue
				}
				if err := notifier.SendAlert(ctx, f); err != nil {
					slog.Warn("failed to send alert", "error", err, "host", in.Host)
				} else {
					_ = markAsReported(cfg.StateDir, f)
				}
			}
		}
	}

	if opts.Submit {
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				handleSubmit(opts, cfg, in)
			}
		}
	}

	// Setup global reports directory
	var globalReportDir string
	home, err := os.UserHomeDir()
	if err == nil {
		globalReportDir = filepath.Join(home, ".bbpts", "results")
		if err := os.MkdirAll(globalReportDir, 0700); err != nil {
			slog.Warn("failed to create global report directory", "dir", globalReportDir, "error", err)
		}
	}

	if opts.SummaryPath != "" {
		if err := analyze.WriteCSVSummary(opts.SummaryPath, insights); err != nil {
			slog.Error("failed to write csv summary", "path", opts.SummaryPath, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteCSVSummary(filepath.Join(globalReportDir, filepath.Base(opts.SummaryPath)), insights); err != nil {
				slog.Warn("failed to write global csv summary", "error", err)
			}
		}
	}

	if opts.ReportH1 != "" {
		if err := analyze.WriteHackerOneCSV(opts.ReportH1, insights); err != nil {
			slog.Error("failed to write HackerOne csv", "path", opts.ReportH1, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteHackerOneCSV(filepath.Join(globalReportDir, filepath.Base(opts.ReportH1)), insights); err != nil {
				slog.Warn("failed to write global HackerOne csv", "error", err)
			}
		}
	}

	if opts.ReportBC != "" {
		if err := analyze.WriteBugcrowdCSV(opts.ReportBC, insights); err != nil {
			slog.Error("failed to write Bugcrowd csv", "path", opts.ReportBC, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteBugcrowdCSV(filepath.Join(globalReportDir, filepath.Base(opts.ReportBC)), insights); err != nil {
				slog.Warn("failed to write global Bugcrowd csv", "error", err)
			}
		}
	}

	if opts.EvidencePath != "" {
		n := opts.EvidenceTopN
		if n <= 0 {
			n = 25
		}
		if err := analyze.WriteEvidenceBundle(opts.EvidencePath, insights, n); err != nil {
			slog.Error("failed to write evidence bundle", "path", opts.EvidencePath, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteEvidenceBundle(filepath.Join(globalReportDir, filepath.Base(opts.EvidencePath)), insights, n); err != nil {
				slog.Warn("failed to write global evidence bundle", "error", err)
			}
		}
	}

	if opts.ObsidianDir != "" {
		if err := analyze.ExportToObsidian(opts.ObsidianDir, insights); err != nil {
			slog.Error("failed to export to obsidian", "dir", opts.ObsidianDir, "error", err)
		}
		if err := analyze.ExportIDORNotes(opts.ObsidianDir, events); err != nil {
			slog.Error("failed to export IDOR notes to obsidian", "dir", opts.ObsidianDir, "error", err)
		}
	}

	// Generate a detailed multi-format report bundle in the local results directory.
	reportDir := "results"
	if strings.TrimSpace(opts.OutputPath) != "" {
		reportDir = filepath.Dir(opts.OutputPath)
	}
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		slog.Warn("failed to ensure detailed report directory", "dir", reportDir, "error", err)
		return
	}
	// Resolve custom report template path
	templatePath := opts.ReportTemplate
	if templatePath == "" {
		templatePath = cfg.ReportTemplatePath
	}

	gen := ui.NewReportGenerator(ui.ReportConfig{
		OutputPath:        reportDir,
		MarkdownPath:      opts.OutputPath,
		IncludeHTML:       true,
		IncludeJSON:       true,
		IncludeMarkdown:   true,
		IncludeBurp:       true,
		IncludeCaido:      true,
		IncludeZAP:        true,
		MinimumScore:      0,
		MinimumConfidence: opts.MinimumConfidence,
		TemplatePath:      templatePath,
		AITriageEnabled:   cfg.AITriageEnabled || opts.AITriage,
		AITriageThreshold: cfg.AITriageThreshold,
		AITriageProvider:  cfg.AITriageProvider,
		AITriageModel:     cfg.AITriageModel,
		AITriageURL:       cfg.AITriageURL,
		AITriageAPIKey:    cfg.APIKeys["gemini"],
		DraftReport:       opts.DraftReport,
	})
	if err := gen.GenerateFullReport(ctx, insights, events, store); err != nil {
		slog.Warn("failed to generate detailed report bundle", "dir", reportDir, "error", err)
	}

	// Also generate in output directory
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		slog.Warn("failed to ensure output directory", "dir", outputDir, "error", err)
	} else {
		genOutput := ui.NewReportGenerator(ui.ReportConfig{
			OutputPath:        outputDir,
			IncludeHTML:       true,
			IncludeJSON:       true,
			IncludeMarkdown:   true,
			IncludeBurp:       true,
			IncludeCaido:      true,
			IncludeZAP:        true,
			MinimumScore:      0,
			MinimumConfidence: opts.MinimumConfidence,
			TemplatePath:      templatePath,
		})
		if err := genOutput.GenerateFullReport(ctx, insights, events, store); err != nil {
			slog.Warn("failed to generate output report bundle", "dir", outputDir, "error", err)
		}
	}

	if globalReportDir != "" {
		genGlobal := ui.NewReportGenerator(ui.ReportConfig{
			OutputPath:        globalReportDir,
			IncludeHTML:       true,
			IncludeJSON:       true,
			IncludeMarkdown:   true,
			IncludeBurp:       true,
			IncludeCaido:      true,
			IncludeZAP:        true,
			MinimumScore:      0,
			MinimumConfidence: opts.MinimumConfidence,
			TemplatePath:      templatePath,
			DraftReport:       opts.DraftReport,
		})
		if err := genGlobal.GenerateFullReport(ctx, insights, events, store); err != nil {
			slog.Warn("failed to generate global detailed report bundle", "dir", globalReportDir, "error", err)
		}
	}



	if store != nil && !opts.JSONOutput {
		nodes, errNodes := store.GetAllAssetNodes(0, 0)
		edges, errEdges := store.GetAllAssetEdges(0, 0)
		if errNodes == nil && errEdges == nil {
			topTargets := analyze.RecommendTargets(nodes, edges)
			if len(topTargets) > 0 {
				fmt.Println("\n=== TOP 10 INVESTIGATION TARGETS (SNIPER SCOPE) ===")
				for i, t := range topTargets {
					fmt.Printf("%d. %s\n", i+1, t.AssetID)
					fmt.Println("Why:")
					for _, w := range t.Why {
						fmt.Printf("✓ %s\n", strings.TrimPrefix(strings.TrimPrefix(w, "✓"), " "))
					}
					fmt.Printf("Score: %.0f\n\n", t.FinalScore)
				}
				fmt.Println("==================================================")
			}

			paths := analyze.GetAttackPaths(nodes, edges)
			topPaths := analyze.RankAttackPaths(paths)
			if len(topPaths) > 10 {
				topPaths = topPaths[:10]
			}
			if len(topPaths) > 0 {
				fmt.Println("\n=== TOP ATTACK PATHS ===")
				for i, p := range topPaths {
					fmt.Printf("%d. [%.0f] %s\n", i+1, p.Score, formatPathValues(p.Path, store))
				}
				fmt.Println("========================")
			}
		} else {
			slog.Warn("failed to fetch nodes/edges for sniper scope/attack path scoring", "errNodes", errNodes, "errEdges", errEdges)
		}
	}

	if opts.CI {
		fail := false
		minSev := strings.ToLower(opts.CIFailOn)
		if minSev == "" {
			minSev = "medium"
		}
		for _, in := range insights {
			severity := strings.ToLower(in.Priority)
			triggered := false
			switch minSev {
			case "low":
				triggered = (severity == "low" || severity == "medium" || severity == "high" || severity == "critical" || in.Score >= 5)
			case "medium":
				triggered = (severity == "medium" || severity == "high" || severity == "critical" || in.Score >= 15)
			case "high":
				triggered = (severity == "high" || severity == "critical" || in.Score >= 25)
			case "critical":
				triggered = (severity == "critical" || in.Score >= 40)
			}
			if triggered {
				slog.Error("CI failure triggered: found high-risk finding", "target", in.Host, "priority", in.Priority, "score", in.Score)
				fail = true
			}
		}
		if fail {
			slog.Error("Exiting with non-zero exit code due to CI failure")
			os.Exit(1)
		}
	}

	// Send "Scan Finished" notification webhook
	if cfg.Notify.DiscordWebhook != "" || cfg.Notify.SlackWebhook != "" || (cfg.Notify.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "") {
		notifier := utils.NewNotifier(utils.Config(notifierConfigFrom(cfg.Notify)))
		finishMsg := fmt.Sprintf("Scan Completed!\nScope: %s\nTotal Targets: %d\nTotal Findings: %d\nNew Findings: %d", scope, len(normalized), len(insights), newCount)
		if err := notifier.SendMessage(finishMsg); err != nil {
			slog.Warn("failed to send scan finished notification", "error", err)
		}
	}

	// Print API quota usage summary
	qg := quota.NewQuotaGuard(cfg.StateDir)
	usage := qg.GetUsage()
	fmt.Println("\n=== API QUOTA USAGE SUMMARY ===")
	fmt.Printf("Shodan calls:  %d\n", usage.ShodanCalls)
	fmt.Printf("Chaos calls:   %d\n", usage.ChaosCalls)
	fmt.Printf("GitHub calls:  %d\n", usage.GitHubCalls)
	fmt.Printf("Reset Date:    %s\n", usage.LastReset.Format("2006-01-02"))
	fmt.Println("================================")
}

func handleSubmit(opts Options, cfg *config.Config, in analyze.Insight) {
	if opts.Scope == "" {
		return
	}
	platform := strings.TrimSpace(cfg.Submit.Platform)
	if platform == "" {
		slog.Warn("submit skipped: submit.platform is not configured", "host", in.Host)
		return
	}

	title := fmt.Sprintf("High Priority Finding: %s", in.Host)
	desc := fmt.Sprintf("Host: %s\nPriority: %s\nTags: %v\n\nReasons:\n%s", in.Host, in.Priority, in.Tags, strings.Join(in.Reasons, "\n"))
	hash := submissionHash(platform, opts.Scope, in)

	if !opts.Submit {
		return
	}
	if alreadySubmitted(cfg.StateDir, hash) {
		slog.Info("submit skipped: finding already submitted", "platform", platform, "host", in.Host, "hash", hash)
		return
	}

	if err := utils.AutoSubmit(platform, opts.Scope, title, desc, "high"); err != nil {
		slog.Warn("submit failed", "platform", platform, "host", in.Host, "error", err)
		return
	}
	if err := markSubmitted(cfg.StateDir, hash); err != nil {
		slog.Warn("failed to record submit marker", "hash", hash, "error", err)
	}
}

func submissionHash(platform, scope string, in analyze.Insight) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(platform)),
		strings.ToLower(strings.TrimSpace(scope)),
		strings.ToLower(strings.TrimSpace(in.DedupeKey)),
		strings.ToLower(strings.TrimSpace(in.Host)),
		strings.Join(in.Tags, ","),
		strings.Join(in.Reasons, "\n"),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:])
}

func submissionMarkerPath(stateDir, hash string) string {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = filepath.Join(".", "results", "utils")
	}
	return filepath.Join(stateDir, "submissions", hash+".submitted")
}

func alreadySubmitted(stateDir, hash string) bool {
	_, err := os.Stat(submissionMarkerPath(stateDir, hash))
	return err == nil
}

func markSubmitted(stateDir, hash string) error {
	path := submissionMarkerPath(stateDir, hash)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0600)
}

func formatPathValues(path []string, store *storage.Storage) string {
	if len(path) == 0 {
		return ""
	}
	if store == nil {
		return strings.Join(path, " -> ")
	}
	nodes, err := store.GetNodesByIDs(path)
	if err != nil || len(nodes) == 0 {
		return strings.Join(path, " -> ")
	}
	nodeMap := make(map[string]string)
	for _, n := range nodes {
		nodeMap[n.ID] = n.Value
	}
	var resolved []string
	for _, id := range path {
		val, exists := nodeMap[id]
		if exists {
			resolved = append(resolved, val)
		} else {
			resolved = append(resolved, id)
		}
	}
	return strings.Join(resolved, " -> ")
}

func hasBeenReported(stateDir string, finding utils.Finding) bool {
	if stateDir == "" {
		return false
	}
	historyPath := filepath.Join(stateDir, "alert_history.txt")

	// Calculate a unique hash for the finding
	hashInput := fmt.Sprintf("%s|%s|%s", finding.Host, finding.Priority, strings.Join(finding.Reasons, ","))
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

	// Read existing hashes
	data, err := os.ReadFile(historyPath)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == hash {
				return true
			}
		}
	}
	return false
}

func markAsReported(stateDir string, finding utils.Finding) error {
	if stateDir == "" {
		return nil
	}
	_ = os.MkdirAll(stateDir, 0700)
	historyPath := filepath.Join(stateDir, "alert_history.txt")

	hashInput := fmt.Sprintf("%s|%s|%s", finding.Host, finding.Priority, strings.Join(finding.Reasons, ","))
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

	f, err := os.OpenFile(historyPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(hash + "\n")
	return err
}


