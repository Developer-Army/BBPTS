package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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
	AssetStore         string
	Checkpoint         *utils.Checkpoint
	QuotaGuard         *utils.QuotaGuard
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
			case "discovery", "subdomain", "domain-info", "vhost", "spa_route", "link", "js_file", "api_endpoint", "websocket_endpoint", "external_js":
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

	if len(allErrs) > 0 {
		return allEvents, errors.Join(allErrs...)
	}
	return allEvents, nil
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
