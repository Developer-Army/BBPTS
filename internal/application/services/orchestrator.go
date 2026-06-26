package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

// Notifier defines an interface for sending alerts.
type Notifier interface {
	SendAlert(ctx context.Context, finding utils.Finding) error
}

// ProgressReporter defines an interface for reporting pipeline progress.
type ProgressReporter interface {
	ReportStage(stage int, tools int, targets int, complete bool)
	ReportStageTools(stage int, tools []string)
}

// Config holds runtime parameters for the recon orchestrator.
type Config struct {
	ToolNames          []string
	Threads            int
	Verbose            bool
	RateLimit          int
	Proxies            []string
	ProxyURL           string
	ProxyInsecure      bool
	APIKeys            map[string]string
	WordlistsDir       string
	TmpResultsDir      string
	Reporter           ProgressReporter
	Notifier           Notifier
	Fleet              FleetConfig
	EventBus           queue.EventBus
	Timeout            time.Duration
	CacheEnabled       bool
	ToolRateLimits     map[string]int
	AutoUpdate         bool
	ContainerMode      bool
	DockerImages       map[string]string
	MockMode           bool
	InsecureSkipVerify bool
	DryRun             bool
	ExploitSQLI        bool
	ForceHTTP1         bool
	AssetStore         string
	Checkpoint         *utils.Checkpoint
	QuotaGuard         *utils.QuotaGuard
	FPConfidenceThreshold int
	FPKeepSuppressed      bool
	FPAudit               bool
}

// FleetConfig holds Axiom distributed fleet configuration.
type FleetConfig struct {
	Enabled     bool
	WorkerMesh  bool
	FleetName   string
	FleetSize   int
	DeleteAfter bool
	ProxyURL    string
}

// Orchestrator manages the staged execution of reconnaissance tools.
type Orchestrator struct {
	config          Config
	tools           []Tool
	limiter         *network.Limiter
	fleetRunner     *AxiomRunner
	proxyFeeder     *ProxyFeeder
	bus             queue.EventBus
	cache           *ResultCache
	circuitBreakers *network.CircuitBreakerRegistry
	scopeGuard      *normalize.ScopeGuard
	assetStoreMu    sync.Mutex
	storage         *orchestratorStorage
}

type eventReporter interface {
	ReportEvent(source, target, eventType string, properties map[string]string)
}

type toolStatusReporter interface {
	ReportToolStatus(tool, status, detail string)
}

type failureReporter interface {
	ReportFailure(tool, detail string)
}

// NewOrchestrator creates a new staged pipeline orchestrator with rate limiting.
func NewOrchestrator(config Config) *Orchestrator {
	tools := []Tool{}
	for _, name := range config.ToolNames {
		if tool, ok := GetToolByName(name); ok {
			tools = append(tools, tool)
			continue
		}
		slog.Warn("unknown tool skipped", "tool", strings.TrimSpace(name))
	}

	limiter := network.New(config.RateLimit)

	var fleetRunner *AxiomRunner
	if config.Fleet.Enabled {
		var err error
		fleetRunner, err = New(AxiomConfig{
			Enabled:     config.Fleet.Enabled,
			FleetName:   config.Fleet.FleetName,
			FleetSize:   config.Fleet.FleetSize,
			DeleteAfter: config.Fleet.DeleteAfter,
		})
		if err != nil {
			slog.Error("failed to initialize axiom fleet runner", "error", err)
		}
	}

	eventBus := config.EventBus
	if eventBus == nil {
		eventBus = queue.New()
	}

	if config.Fleet.WorkerMesh {
		hm := NewHealthMonitor(eventBus)
		hm.Start()
	}

	o := &Orchestrator{
		config:      config,
		tools:       tools,
		limiter:     limiter,
		fleetRunner: fleetRunner,
		bus:         eventBus,
		circuitBreakers: network.NewCircuitBreakerRegistry(
			network.DefaultCircuitBreakerConfig(),
		),
		storage:     &orchestratorStorage{},
	}

	if config.ProxyURL != "" {
		feeder, err := NewProxyFeeder(config.ProxyURL, config.ProxyInsecure)
		if err != nil {
			slog.Error("failed to initialize proxy feeder", "error", err)
		} else {
			o.proxyFeeder = feeder
		}
	}

	if config.CacheEnabled {
		cache, err := NewResultCache(DefaultCacheConfig())
		if err != nil {
			slog.Warn("result cache unavailable", "error", err)
		} else {
			o.cache = cache
		}
	}

	return o
}

// Close releases resources held by the orchestrator.
func (o *Orchestrator) Close() {
	if o.limiter != nil {
		o.limiter.Stop()
	}
	if o.fleetRunner != nil {
		o.fleetRunner.Close()
	}
}

// Run executes the full staged recon pipeline, cascading discovered targets forward.
func (o *Orchestrator) Run(ctx context.Context, initialTargets []string) ([]Event, error) {
	if len(o.tools) == 0 {
		return nil, errors.New("no recon tools configured")
	}

	var spanID string
	ctx, spanID = telemetry.InternalTracer.StartSpan(ctx, "Orchestrator.Run", "")
	defer func() {
		telemetry.InternalTracer.EndSpan(spanID, map[string]interface{}{
			"targets_count": len(initialTargets),
		})
	}()

	ctx = WithAPIKeys(ctx, o.config.APIKeys)
	ctx = WithWordlistsDir(ctx, o.config.WordlistsDir)
	ctx = WithTmpResultsDir(ctx, o.config.TmpResultsDir)
	ctx = WithRateLimit(ctx, o.config.RateLimit)
	ctx = WithToolRateLimits(ctx, o.config.ToolRateLimits)
	ctx = WithAutoUpdate(ctx, o.config.AutoUpdate)
	ctx = WithContainerMode(ctx, o.config.ContainerMode)
	ctx = WithDockerImages(ctx, o.config.DockerImages)
	ctx = WithInsecure(ctx, o.config.InsecureSkipVerify)
	ctx = WithDryRun(ctx, o.config.DryRun)
	ctx = WithExploitSQLI(ctx, o.config.ExploitSQLI)
	ctx = WithForceHTTP1(ctx, o.config.ForceHTTP1)
	if o.config.QuotaGuard != nil {
		ctx = WithQuotaGuard(ctx, o.config.QuotaGuard)
	}

	if err := o.ensureTmpResultsDir(); err != nil {
		slog.Warn("failed to initialize tmp results directory", "dir", o.config.TmpResultsDir, "error", err)
	}

	if o.fleetRunner != nil {
		if err := o.fleetRunner.ProvisionFleet(ctx); err != nil {
			return nil, fmt.Errorf("fleet provisioning failed: %w", err)
		}
	}

	threads := o.config.Threads
	if threads < 1 {
		threads = 1
	}

	stages := make(map[int][]Tool)
	for _, tool := range o.tools {
		st := GetToolStage(tool.Name())
		stages[st] = append(stages[st], tool)
	}

	var allEvents []Event
	var allErrs []error
	currentTargets := initialTargets
	scopeGuard := normalize.NewScopeGuard(initialTargets)
	o.scopeGuard = scopeGuard

	// Resume from checkpoint if stage-level checkpoints exist
	if o.config.Checkpoint != nil && len(o.config.Checkpoint.CompletedStages) > 0 {
		if len(o.config.Checkpoint.CurrentTargets) > 0 {
			currentTargets = o.config.Checkpoint.CurrentTargets
		}
		for _, ev := range o.config.Checkpoint.Events {
			allEvents = append(allEvents, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		}
		slog.Info("Resuming orchestrator execution from checkpoint",
			"completed_stages", o.config.Checkpoint.CompletedStages,
			"current_targets", len(currentTargets),
			"events_loaded", len(allEvents),
		)
	}

	customOrder := []int{0, 1, 2, 3, 4}
	for _, stageNum := range customOrder {
		stageTools := stages[stageNum]
		if len(stageTools) == 0 {
			continue
		}

		// Filter stageTools based on discoveries (Dynamic Gating)
		var gatedTools []Tool
		for _, tool := range stageTools {
			if o.shouldSkipTool(tool.Name(), currentTargets, allEvents) {
				slog.Info("Dynamic Gating: skipping tool based on discoveries", "tool", tool.Name(), "stage", stageNum)
				continue
			}
			gatedTools = append(gatedTools, tool)
		}
		stageTools = gatedTools
		if len(stageTools) == 0 {
			slog.Info("stage skipped: all tools gated", "stage", stageNum)
			continue
		}

		// Check if stage is already completed
		isCompleted := false
		if o.config.Checkpoint != nil {
			o.config.Checkpoint.Mu.Lock()
			for _, cs := range o.config.Checkpoint.CompletedStages {
				if cs == stageNum {
					isCompleted = true
					break
				}
			}
			o.config.Checkpoint.Mu.Unlock()
		}
		if isCompleted {
			slog.Info("stage skipped: already completed in checkpoint", "stage", stageNum)
			continue
		}

		if len(currentTargets) == 0 {
			slog.Debug("stage skipped: no targets", "stage", stageNum)
			continue
		}

		slog.Info("starting pipeline stage",
			"stage", stageNum,
			"tools", len(stageTools),
			"targets", len(currentTargets),
			"fleet_mode", o.fleetRunner != nil,
		)
		if o.config.Reporter != nil {
			o.config.Reporter.ReportStage(stageNum, len(stageTools), len(currentTargets), false)
			toolNames := make([]string, len(stageTools))
			for i, t := range stageTools {
				toolNames[i] = t.Name()
			}
			o.config.Reporter.ReportStageTools(stageNum, toolNames)
		}

		events, errs := o.runStage(ctx, stageTools, currentTargets, threads)
		events = filterEventsInScope(scopeGuard, events)
		allEvents = append(allEvents, events...)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}

		// Wire interactsh OOB URL into context for downstream tools (nuclei, dalfox)
		for _, ev := range events {
			if ev.Type == "oob_session" && ev.Source == "interactsh" && ev.Target != "" {
				ctx = WithInteractshOOBURL(ctx, ev.Target)
				slog.Info("Interactsh OOB URL injected into context", "url", ev.Target)
				break
			}
		}
		for _, ev := range events {
			if ev.Source == "wafw00f" {
				if waf := strings.TrimSpace(ev.Properties["waf_type"]); waf != "" {
					ctx = WithWAFContext(ctx, waf)
					slog.Info("WAF context injected into downstream active tools", "waf", waf)
					break
				}
			}
		}

		nextTargets := append(currentTargets, extractTargets(events)...)
		normalizedTargets := normalize.DeduplicateAndPreserveURLs(nextTargets)
		currentTargets = scopeGuard.Filter(normalizedTargets)

		if stageNum == 2 {
			liveWebTargets := extractLiveWebTargets(events)
			if len(liveWebTargets) > 0 {
				currentTargets = scopeGuard.Filter(normalize.DeduplicateAndPreserveURLs(liveWebTargets))
				slog.Info("gating downstream stages with live httpx targets", "live_targets", len(currentTargets))
			} else {
				slog.Warn("httpx produced no live web targets; keeping cascaded targets for downstream stages")
			}
		}
		if len(normalizedTargets) > len(currentTargets) {
			blocked := len(normalizedTargets) - len(currentTargets)
			slog.Warn("Scope Guard triggered! Blocked out-of-scope targets", "blocked_count", blocked, "stage", stageNum)
			o.reportFailure("scope-guard", fmt.Sprintf("blocked %d out-of-scope targets", blocked))
		}

		slog.Info("pipeline stage complete",
			"stage", stageNum,
			"events_found", len(events),
			"cascaded_targets", len(currentTargets),
		)
		if o.config.Reporter != nil {
			o.config.Reporter.ReportStage(stageNum, len(stageTools), len(currentTargets), true)
		}

		for _, ev := range events {
			o.bus.Publish(queue.Event{Target: ev.Target, Source: ev.Source, Type: ev.Type, Properties: ev.Properties})

			var coreType string
			switch ev.Type {
			case "discovery", "subdomain", "domain-info", "vhost", "spa_route", "link", "js_file", "api_endpoint", "websocket_endpoint", "external_js", "config_file", "internal_endpoint", "email_found", "email_pattern", "github_account":
				coreType = queue.EventAssetDiscovered
			case "service", "port_open", "graphql_endpoint", "oob_session":
				coreType = queue.EventHostAlive
			case "vulnerability", "secret_exposed":
				coreType = queue.EventFindingCreated
			}
			if coreType != "" {
				o.bus.Publish(queue.Event{
					Target:     ev.Target,
					Source:     ev.Source,
					Type:       coreType,
					Properties: ev.Properties,
				})
			}
		}

		if o.proxyFeeder != nil && stageNum >= 3 {
			webURLs := []string{}
			for _, ev := range events {
				if strings.HasPrefix(ev.Target, "http") {
					webURLs = append(webURLs, ev.Target)
				}
			}
			if len(webURLs) > 0 {
				o.proxyFeeder.FeedURLs(ctx, webURLs, o.config.Threads)
			}
		}

		if stageNum == 4 {
			swaggerEvents, swaggerErrs := o.processSwaggerSpecs(ctx, allEvents, threads)
			if len(swaggerEvents) > 0 {
				allEvents = append(allEvents, swaggerEvents...)
				for _, ev := range swaggerEvents {
					o.bus.Publish(queue.Event{Target: ev.Target, Source: ev.Source, Type: ev.Type, Properties: ev.Properties})

					var coreType string
					switch ev.Type {
					case "discovery", "subdomain", "domain-info", "vhost", "spa_route", "link", "js_file", "api_endpoint", "websocket_endpoint", "external_js", "config_file", "internal_endpoint", "email_found", "email_pattern", "github_account":
						coreType = queue.EventAssetDiscovered
					case "service", "port_open", "graphql_endpoint", "oob_session":
						coreType = queue.EventHostAlive
					case "vulnerability", "secret_exposed":
						coreType = queue.EventFindingCreated
					}
					if coreType != "" {
						o.bus.Publish(queue.Event{
							Target:     ev.Target,
							Source:     ev.Source,
							Type:       coreType,
							Properties: ev.Properties,
						})
					}
				}
			}
			if len(swaggerErrs) > 0 {
				allErrs = append(allErrs, swaggerErrs...)
			}
		}

		// Save checkpoint at the end of each stage
		if o.config.Checkpoint != nil {
			o.config.Checkpoint.Mu.Lock()
			alreadyAdded := false
			for _, cs := range o.config.Checkpoint.CompletedStages {
				if cs == stageNum {
					alreadyAdded = true
					break
				}
			}
			if !alreadyAdded {
				o.config.Checkpoint.CompletedStages = append(o.config.Checkpoint.CompletedStages, stageNum)
			}
			o.config.Checkpoint.CurrentTargets = currentTargets
			checkpointEvents := make([]recon.Event, len(allEvents))
			for idx, ev := range allEvents {
				checkpointEvents[idx] = recon.Event{
					Target:     ev.Target,
					Source:     ev.Source,
					Type:       ev.Type,
					Properties: ev.Properties,
				}
			}
			o.config.Checkpoint.Events = checkpointEvents
			o.config.Checkpoint.Mu.Unlock()
			o.config.Checkpoint.Save()
		}
	}

	if o.config.MockMode {
		allEvents = injectMockComplianceEvents(initialTargets, o.config.TmpResultsDir, allEvents)
	}

	allEvents = CorroborateEvents(allEvents)
	kept, suppressed := o.runScoringPass(allEvents)
	o.notify(kept)
	o.storage.SaveEvents(kept)
	_ = suppressed // keep variable bound

	if len(allErrs) > 0 {
		return kept, errors.Join(allErrs...)
	}
	return kept, nil
}

type orchestratorStorage struct{}

func (s *orchestratorStorage) SaveEvents(events []Event) {}

func (o *Orchestrator) notify(events []Event) {}

func (o *Orchestrator) runScoringPass(events []Event) (kept []Event, suppressed []Event) {
	threshold := o.config.FPConfidenceThreshold

	var scored []ScoredEvent
	for _, ev := range events {
		score := ScoreEvent(ev)
		if ev.Properties == nil {
			ev.Properties = make(map[string]string)
		}
		ev.Properties["confidence_score"] = strconv.Itoa(score)
		
		suppressedFlag := score < threshold
		ev.Properties["suppressed"] = strconv.FormatBool(suppressedFlag)

		scoredEv := ScoredEvent{
			Event:           ev,
			ConfidenceScore: score,
			Suppressed:      suppressedFlag,
		}
		scored = append(scored, scoredEv)
	}

	if o.config.FPAudit {
		auditPath := "suppressed.jsonl"
		if o.config.TmpResultsDir != "" {
			auditPath = filepath.Join(o.config.TmpResultsDir, "suppressed.jsonl")
		}
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			defer f.Close()
			for _, se := range scored {
				if se.Suppressed {
					data, err := json.Marshal(se)
					if err == nil {
						_, _ = f.Write(append(data, '\n'))
					}
				}
			}
		} else {
			slog.Warn("failed to open suppressed.jsonl for audit", "error", err)
		}
	}

	var keptScored []ScoredEvent
	if o.config.FPKeepSuppressed {
		keptScored = scored
	} else {
		keptScored = Filter(scored)
	}

	for _, se := range keptScored {
		kept = append(kept, se.Event)
	}
	for _, se := range scored {
		if se.Suppressed {
			suppressed = append(suppressed, se.Event)
		}
	}

	return kept, suppressed
}

// Bus returns the internal event bus.
func (o *Orchestrator) Bus() queue.EventBus {
	return o.bus
}

func (o *Orchestrator) ensureTmpResultsDir() error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" {
		return nil
	}
	return os.MkdirAll(o.config.TmpResultsDir, 0700)
}

func (o *Orchestrator) shouldSkipTool(name string, targets []string, events []Event) bool {
	name = strings.ToLower(strings.TrimSpace(name))

	// 1. Skip TLS tools if no port 443/8443 or HTTPS target was found
	if name == "tlsx" {
		hasTLS := false
		for _, t := range targets {
			if strings.HasPrefix(strings.ToLower(t), "https://") || strings.Contains(t, ":443") || strings.Contains(t, ":8443") {
				hasTLS = true
				break
			}
		}
		for _, ev := range events {
			if ev.Type == "port_open" && (ev.Properties["port"] == "443" || ev.Properties["port"] == "8443") {
				hasTLS = true
				break
			}
		}
		return !hasTLS
	}

	// 2. Skip dalfox if no query parameters crawled
	if name == "dalfox" {
		hasQueryParams := false
		for _, t := range targets {
			if strings.Contains(t, "?") {
				hasQueryParams = true
				break
			}
		}
		return !hasQueryParams
	}

	// 3. Skip gobuster / ffuf / feroxbuster if no directories/web URLs resolved
	if name == "gobuster" || name == "ffuf" || name == "feroxbuster" {
		hasWeb := false
		for _, t := range targets {
			if strings.HasPrefix(strings.ToLower(t), "http://") || strings.HasPrefix(strings.ToLower(t), "https://") {
				hasWeb = true
				break
			}
		}
		return !hasWeb
	}

	return false
}

func (o *Orchestrator) processSwaggerSpecs(ctx context.Context, allEvents []Event, threads int) ([]Event, []error) {
	var newEvents []Event
	var errs []error

	swaggerPattern := regexp.MustCompile(`(?i)(/api-docs|swagger\.json|openapi\.yaml|openapi\.json|openapi\.yml|swagger\.yaml|swagger\.yml)`)
	seenSpecs := make(map[string]bool)
	var specURLs []string

	for _, ev := range allEvents {
		if swaggerPattern.MatchString(ev.Target) && strings.HasPrefix(ev.Target, "http") {
			if !seenSpecs[ev.Target] {
				seenSpecs[ev.Target] = true
				specURLs = append(specURLs, ev.Target)
			}
		}
	}

	if len(specURLs) == 0 {
		return nil, nil
	}

	parser := NewSwaggerParser(10 * time.Second)
	var extractedURLs []string

	for _, specURL := range specURLs {
		slog.Info("Discovered API Spec - parsing for endpoints and auth schemes", "url", specURL)
		events, targets, err := parser.FetchAndParse(ctx, specURL)
		if err != nil {
			slog.Error("failed to fetch or parse API spec", "url", specURL, "error", err)
			errs = append(errs, fmt.Errorf("spec %s: %w", specURL, err))
			continue
		}

		newEvents = append(newEvents, events...)
		extractedURLs = append(extractedURLs, targets...)
	}

	if len(extractedURLs) == 0 {
		return newEvents, errs
	}

	// Filter in-scope targets and deduplicate
	var allowedTargets []string
	seenTargets := make(map[string]bool)
	for _, t := range extractedURLs {
		if o.scopeGuard == nil || o.scopeGuard.IsAllowed(t) {
			if !seenTargets[t] {
				seenTargets[t] = true
				allowedTargets = append(allowedTargets, t)
			}
		}
	}

	if len(allowedTargets) == 0 {
		return newEvents, errs
	}

	// Find nuclei and dalfox tools from active tools
	var nucleiTool Tool
	var dalfoxTool Tool
	for _, t := range o.tools {
		if t.Name() == "nuclei" {
			nucleiTool = t
		} else if t.Name() == "dalfox" {
			dalfoxTool = t
		}
	}

	if nucleiTool != nil {
		slog.Info("Running nuclei on Swagger-discovered endpoints", "targets_count", len(allowedTargets))
		nEvents, err := nucleiTool.Run(ctx, allowedTargets, threads)
		if err != nil {
			slog.Error("failed to run nuclei on swagger endpoints", "error", err)
			errs = append(errs, err)
		} else {
			newEvents = append(newEvents, nEvents...)
		}
	}

	if dalfoxTool != nil {
		var dalfoxTargets []string
		for _, t := range allowedTargets {
			if strings.Contains(t, "?") {
				dalfoxTargets = append(dalfoxTargets, t)
			}
		}
		if len(dalfoxTargets) > 0 {
			slog.Info("Running dalfox on Swagger-discovered endpoints", "targets_count", len(dalfoxTargets))
			dEvents, err := dalfoxTool.Run(ctx, dalfoxTargets, threads)
			if err != nil {
				slog.Error("failed to run dalfox on swagger endpoints", "error", err)
				errs = append(errs, err)
			} else {
				newEvents = append(newEvents, dEvents...)
			}
		}
	}

	return newEvents, errs
}
