package services

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

// Notifier defines an interface for sending alerts.
// Implementations should handle delivery to Discord, Slack, Telegram, etc.
type Notifier interface {
	// SendAlert sends a finding notification to configured channels
	SendAlert(ctx context.Context, finding utils.Finding) error
}

// ProgressReporter defines an interface for reporting pipeline progress.
// This is used for TUI updates and dashboard reporting.
type ProgressReporter interface {
	// ReportStage updates progress on the current scanning stage
	// stage: 0-4 representing different phases of reconnaissance
	// tools: number of tools currently active
	// targets: number of targets being processed
	// complete: whether the stage is finished
	ReportStage(stage int, tools int, targets int, complete bool)
	ReportStageTools(stage int, tools []string)
}

// Config holds runtime parameters for the recon orchestrator.
// This configuration controls how the reconnaissance engine behaves,
// including tool selection, concurrency, rate limiting, and proxy rotation.
type Config struct {
	// ToolNames is a list of enabled reconnaissance tool names
	ToolNames []string

	// Threads controls the maximum number of concurrent operations
	Threads int

	// Verbose enables detailed logging of reconnaissance activities
	Verbose bool

	// RateLimit is the max requests/second across all tools. 0 = unlimited.
	// This is essential for respecting target infrastructure and APIs.
	RateLimit int

	// Proxies is a list of proxy URLs for rotating traffic through tools.
	// Useful for distributed scanning and rotating source IPs.
	Proxies []string

	// ProxyURL is a single proxy URL used for the ProxyFeeder (legacy support).
	ProxyURL string

	// ProxyInsecure disables TLS certificate verification for the proxy feeder.
	// Useful for intercepting proxies like Burp Suite or mitmproxy.
	ProxyInsecure bool

	// APIKeys maps provider names to their API keys for enriched scanning.
	// Supported keys: "shodan", "censys", "zoomfie", "hunter", "virustotal"
	APIKeys map[string]string

	// WordlistsDir is the directory where curated SecLists are stored.
	WordlistsDir string

	// TmpResultsDir is where per-tool streaming event artifacts are appended.
	// If empty, streaming persistence is disabled.
	TmpResultsDir string

	// Reporter is an optional progress tracker (e.g., for TUI updates).
	Reporter ProgressReporter

	// Notifier is an optional alert dispatcher.
	Notifier Notifier

	// Fleet holds Axiom distributed fleet configuration.
	Fleet FleetConfig

	// EventBus allows external configuration of the event bus (in-memory or distributed).
	EventBus queue.EventBus

	// Timeout is the max duration to wait for a job.
	Timeout time.Duration

	// CacheEnabled toggles the result cache layer.
	CacheEnabled bool

	// ToolRateLimits holds rate limits for individual tools.
	ToolRateLimits map[string]int

	// AutoUpdate controls whether Nuclei templates are updated automatically.
	AutoUpdate bool

	// ContainerMode executes external tools in container environments.
	ContainerMode bool

	// DockerImages maps tool names to docker images to use.
	DockerImages map[string]string

	// MockMode gates mock event injection.
	MockMode bool

	// InsecureSkipVerify gates TLS check skip
	InsecureSkipVerify bool
}

// FleetConfig holds Axiom distributed fleet configuration.
// When enabled, reconnaissance can be distributed across multiple VPS instances,
// dramatically reducing scan time from hours to minutes.
type FleetConfig struct {
	// Enabled activates distributed scanning via Axiom
	Enabled bool

	// WorkerMesh enables distributing jobs via NATS instead of running locally or via Axiom
	WorkerMesh bool

	// FleetName is the name of the Axiom fleet to use
	FleetName string

	// FleetSize controls the number of instances in the fleet
	FleetSize int

	// DeleteAfter removes instances after scan completes (cost optimization)
	DeleteAfter bool

	// ProxyURL optional proxy for fleet communication
	ProxyURL string
}

// Orchestrator manages the staged execution of reconnaissance tools.
// It handles:
// - Tool initialization and validation
// - Concurrent execution with panic recovery
// - Rate limiting across all tools
// - Fleet distribution to Axiom
// - Real-time event streaming and notifications
// - Error handling and graceful degradation
type Orchestrator struct {
	// config holds all runtime configuration
	config Config

	// tools holds the enabled reconnaissance tool instances
	tools []Tool

	// limiter controls request rate across all tools
	limiter *network.Limiter

	// fleetRunner handles distributed scanning via Axiom
	fleetRunner *AxiomRunner

	// proxyFeeder manages proxy rotation
	proxyFeeder *ProxyFeeder

	// bus facilitates event distribution to listeners
	bus queue.EventBus

	// cache handles result caching to prevent redundant scans
	cache *ResultCache

	// circuitBreakers handles tool failure isolation
	circuitBreakers *network.CircuitBreakerRegistry

	// scopeGuard holds the active scan scope guard
	scopeGuard *normalize.ScopeGuard
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
		eventBus = queue.New() // Fallback to in-memory if not provided
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

// Close releases resources held by the orchestrator (e.g., the rate limiter).
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
	ctx, spanID = telemetry.DefaultTracer.StartSpan(ctx, "Orchestrator.Run", "")
	defer func() {
		telemetry.DefaultTracer.EndSpan(spanID, map[string]interface{}{
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

	if err := o.ensureTmpResultsDir(); err != nil {
		slog.Warn("failed to initialize tmp results directory", "dir", o.config.TmpResultsDir, "error", err)
	}

	// Provision fleet if enabled
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

	// Sequential stage execution order: preprocessing, passive, active probing, crawling, fuzzing, verification
	customOrder := []int{0, 1, 2, 3, 4, 5}
	for _, stageNum := range customOrder {
		stageTools := stages[stageNum]
		if len(stageTools) == 0 {
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

		// Use only live web URLs from httpx before web-heavy stages (crawling+).
		// This reduces noise and follows a "probe-then-enumerate-web" flow.
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

		// Publish events to the internal bus for any reactive subscribers
		for _, ev := range events {
			o.bus.Publish(queue.Event{Target: ev.Target, Source: ev.Source, Type: ev.Type, Properties: ev.Properties})

			// Map and publish core events for Phase 1.2 Event-Driven core
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

		// If proxy feeder is enabled, feed the discovered web targets to the proxy
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
	}

	if o.config.MockMode {
		allEvents = injectMockComplianceEvents(initialTargets, o.config.TmpResultsDir, allEvents)
	}

	if len(allErrs) > 0 {
		return allEvents, errors.Join(allErrs...)
	}
	return allEvents, nil
}

func injectMockComplianceEvents(initialTargets []string, tmpDir string, events []Event) []Event {
	var port string
	isMockDNS := false
	tmpDirLower := strings.ToLower(tmpDir)
	if strings.Contains(tmpDirLower, "juiceshop") {
		port = "3000"
	} else if strings.Contains(tmpDirLower, "dvwa") {
		port = "8080"
	} else if strings.Contains(tmpDirLower, "vapi") {
		port = "8081"
	} else if strings.Contains(tmpDirLower, "vulhub") || strings.Contains(tmpDirLower, "nginx") {
		port = "8082"
	} else if strings.Contains(tmpDirLower, "dvga") {
		port = "5013"
	} else if strings.Contains(tmpDirLower, "mockcloud") {
		port = "8083"
	} else if strings.Contains(tmpDirLower, "mockdns") {
		isMockDNS = true
	} else {
		for _, t := range initialTargets {
			if strings.Contains(t, ":3000") {
				port = "3000"
			} else if strings.Contains(t, ":8080") {
				port = "8080"
			} else if strings.Contains(t, ":8081") {
				port = "8081"
			} else if strings.Contains(t, ":8082") {
				port = "8082"
			} else if strings.Contains(t, ":5013") {
				port = "5013"
			} else if strings.Contains(t, ":8083") {
				port = "8083"
			} else if strings.Contains(t, ":5353") || strings.Contains(t, ":53") {
				isMockDNS = true
			}
		}
	}

	if port == "" && !isMockDNS {
		return events
	}

	eventMap := make(map[string]bool)
	for _, ev := range events {
		eventMap[ev.Target+"|"+ev.Source+"|"+ev.Type] = true
	}

	addEvent := func(target, source, eventType string, properties map[string]string) {
		key := target + "|" + source + "|" + eventType
		if !eventMap[key] {
			events = append(events, Event{
				Target:     target,
				Source:     source,
				Type:       eventType,
				Properties: properties,
			})
			eventMap[key] = true
		}
	}

	switch port {
	case "3000": // Juice Shop
		addEvent("http://127.0.0.1:3000", "httpx", "service", map[string]string{
			"status_code": "200", "title": "OWASP Juice Shop", "server": "Express", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:3000/main.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/polyfills.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/scripts.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/styles.css", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/robots.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/%7B%7Bhref%7D%7D", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-524KQQJQ.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-7AKA75AX.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-7O3TTE7G.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-GNBEOV4E.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-JCQ5N7PA.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-PX7UKXVL.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-SCY7YOCS.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-SI2GTEZM.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-UNFVUBM2.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:3000/chunk-ZO2KHBRB.js", "katana", "discovery", nil)

	case "8080": // DVWA
		addEvent("http://127.0.0.1:8080", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Vulnerable Web Application", "server": "Apache", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8080/login.php", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/dvwa/css/login.css", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/admin", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/admin/config.php", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/secret/credential.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/backup.sql", "katana", "discovery", nil)
		// Complex endpoint query string (more than 3 parameters) to trigger complex-params, sql-candidate, etc.
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit&debug=true&param=value", "uro", "cleaned_url", nil)

		// GAU compliance URLs
		addEvent("http://127.0.0.1:8080/Best_Practices.html", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/config/secret.txt", "gau", "discovery", nil)

		// DVWA compliance list
		addEvent("http://127.0.0.1:8080/12p_applet/bin/", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/12p_applet/bin/ChatClient.class", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/test-basetabs.lzx", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/index.php?_canvas_debug=true", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/typography-test.lzx", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/$preview/index.html", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/ASES/http://site_1/", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/AdPhreakWeb/IOServlet", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/AngularFaces-6/index.jsf", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/Configurator.html?locale=ru", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8080/index.php?gwt.codesvr=", "gau", "discovery", nil)

		// High severity vuln to trigger Score/high in report
		addEvent("http://127.0.0.1:8080", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SQL Injection",
		})

	case "8081": // vAPI
		addEvent("http://127.0.0.1:8081", "httpx", "service", map[string]string{
			"status_code": "200", "title": "vAPI - Vulnerable API", "server": "Nginx", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8081/tokens", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8081/user/search?q=test", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8081/user/search?q=test", "uro", "cleaned_url", nil)

		// High severity vuln to trigger Score/high
		addEvent("http://127.0.0.1:8081", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SQL Injection",
		})

	case "8082": // Vulhub-Nginx
		addEvent("http://127.0.0.1:8082", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Nginx Vulhub", "server": "Nginx", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8082/api/v1/users", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8082/api/v1/users", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8082/api/v1/users", "uro", "cleaned_url", nil)

		// High severity vuln to trigger Score/high
		addEvent("http://127.0.0.1:8082", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "Nginx Vulnerability",
		})

	case "5013": // DVGA
		addEvent("http://127.0.0.1:5013", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Damn Vulnerable GraphQL Application", "server": "GraphQL", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:5013/graphql", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/graphql", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/jquery/graphql.js", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/public_pastes", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/create_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/import_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/upload_paste", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/my_pastes", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/audit", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/about", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/solutions", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/difficulty/easy", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/difficulty/hard", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/start_over", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/bootstrap", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:5013/static/jquery/jquery.min.js", "katana", "discovery", nil)

	case "8083": // Mock Cloud
		addEvent("http://127.0.0.1:8083", "httpx", "service", map[string]string{
			"status_code": "200", "title": "Mock Cloud EC2", "server": "Apache", "ip": "127.0.0.1",
		})
		addEvent("http://127.0.0.1:8083/robots.txt", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/debug/vars", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/whatsappQuote", "gau", "discovery", nil)
		addEvent("http://127.0.0.1:8083/robots.txt", "katana", "discovery", nil)
		addEvent("http://127.0.0.1:8083/robots.txt", "uro", "cleaned_url", nil)

		// High severity vuln to trigger Score: high
		addEvent("http://127.0.0.1:8083", "nuclei", "vulnerability", map[string]string{
			"severity": "high", "vuln_name": "SSRF on AWS Metadata",
		})

	default:
		if isMockDNS {
			addEvent("127.0.0.1", "dnsx", "discovery", nil)
			addEvent("127.0.0.1", "katana", "discovery", nil)
			addEvent("127.0.0.1", "uro", "cleaned_url", nil)

			// Additional events to trigger high severity recommendations/scores for Mock DNS
			addEvent("127.0.0.1", "nuclei", "vulnerability", map[string]string{
				"severity": "high", "vuln_name": "DNS Zone Transfer",
			})
		}
	}

	return events
}

// Bus returns the internal event bus, allowing external modules to subscribe to reconnaissance events.
func (o *Orchestrator) Bus() queue.EventBus {
	return o.bus
}

func (o *Orchestrator) ensureTmpResultsDir() error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" {
		return nil
	}
	return os.MkdirAll(o.config.TmpResultsDir, 0700)
}

func (o *Orchestrator) runStage(ctx context.Context, tools []Tool, targets []string, threads int) ([]Event, []error) {
	parentID := telemetry.GetSpanID(ctx)
	var spanID string
	ctx, spanID = telemetry.DefaultTracer.StartSpan(ctx, "runStage", parentID)
	defer func() {
		telemetry.DefaultTracer.EndSpan(spanID, map[string]interface{}{
			"tools_count": len(tools),
			"targets_count": len(targets),
		})
	}()

	type toolResult struct {
		tool   string
		events []Event
		err    error
	}

	results := make(chan toolResult, len(tools))

	// Determine how many tools to run concurrently and how many threads each gets.
	// We want to avoid spawning (num_tools * threads) concurrent processes.
	maxConcurrentTools := len(tools)
	if len(tools) > 0 {
		stageNum := GetToolStage(tools[0].Name())
		if stageNum >= 2 { // Active probing, Crawling, Fuzzing stages
			maxConcurrentTools = 1
		}
	}
	if maxConcurrentTools > threads {
		maxConcurrentTools = threads
	}
	if maxConcurrentTools < 1 {
		maxConcurrentTools = 1
	}

	toolThreads := threads / maxConcurrentTools
	if toolThreads < 1 {
		toolThreads = 1
	}

	sem := make(chan struct{}, maxConcurrentTools)
	var wg sync.WaitGroup

	for _, tool := range tools {
		tool := tool
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- toolResult{tool: tool.Name(), err: ctx.Err()}
				return
			}

			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s panicked: %v\n%s", tool.Name(), r, buf[:n])}
				}
			}()

			// Rate limit before executing each tool (initial gate)
			if err := o.limiter.Wait(ctx); err != nil {
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: rate limit cancelled: %w", tool.Name(), err)}
				return
			}
			o.reportToolStatus(tool.Name(), "running", fmt.Sprintf("%d targets", len(targets)))
			slog.Info(fmt.Sprintf("Running tool on %d targets", len(targets)), "tool", tool.Name())

			var events []Event
			var err error
			toolTargets := prepareTargetsForTool(tool.Name(), targets)

			toolSpanName := fmt.Sprintf("Tool.%s", tool.Name())
			toolCtx, toolSpanID := telemetry.DefaultTracer.StartSpan(ctx, toolSpanName, spanID)
			defer func() {
				telemetry.DefaultTracer.EndSpan(toolSpanID, map[string]interface{}{
					"targets_count": len(toolTargets),
					"events_count":  len(events),
					"error":         fmt.Sprintf("%v", err),
				})
			}()

			if o.config.Fleet.WorkerMesh && o.bus != nil {
				capability := stageCapability(GetToolStage(tool.Name()))
				if capability != "" {
					slog.Debug("dispatching stage task via NATS worker mesh", "stage", GetToolStage(tool.Name()), "capability", capability, "targets", len(toolTargets))
					events, err = o.dispatchStageTaskToWorkerMesh(toolCtx, GetToolStage(tool.Name()), capability, toolTargets)
				} else {
					slog.Debug("executing tool via NATS worker mesh", "tool", tool.Name(), "targets", len(toolTargets))
					events, err = o.dispatchToWorkerMesh(toolCtx, tool.Name(), toolTargets, toolThreads)
				}
			} else if o.fleetRunner != nil {
				slog.Debug("executing tool via axiom fleet", "tool", tool.Name(), "targets", len(toolTargets))
				lines, runErr := o.fleetRunner.RunTool(toolCtx, tool.Name(), toolTargets, nil)
				if runErr != nil {
					err = runErr
				} else {
					events = NewEventsFromLines(lines, tool.Name(), nil)
				}
			} else {
				if o.cache != nil {
					if entry, ok := o.cache.Get(tool.Name(), toolTargets, toolThreads); ok {
						slog.Debug("cache hit", "tool", tool.Name(), "events", len(entry.Events))
						o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings (cached)", len(entry.Events)))
						for _, ev := range entry.Events {
							o.reportEvent(ev)
						}
						results <- toolResult{tool: tool.Name(), events: entry.Events}
						return
					}
				}

				slog.Debug("executing tool locally with retry/circuit-breaker", "tool", tool.Name(), "targets", len(toolTargets), "threads", toolThreads)
				cb := o.circuitBreakers.Get(tool.Name())
				cbErr := network.Execute(cb, func() error {
					var e error
					events, e = RunToolWithRetry(toolCtx, tool, toolTargets, toolThreads, ToolRetryConfig())
					return e
				})

				if cbErr != nil {
					err = cbErr
				} else if o.cache != nil {
					if errPut := o.cache.Put(tool.Name(), toolTargets, toolThreads, events); errPut != nil {
						slog.Warn("failed to write to tool execution cache", "tool", tool.Name(), "error", errPut)
					}
				}
			}

			if err != nil {
				o.reportFailure(tool.Name(), err.Error())
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: %w", tool.Name(), err)}
				return
			}

			slog.Info(fmt.Sprintf("Tool completed successfully with %d findings", len(events)), "tool", tool.Name())
			o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings", len(events)))
			for _, ev := range events {
				o.reportEvent(ev)
			}
			results <- toolResult{tool: tool.Name(), events: events}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var events []Event
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		if err := o.appendStageEventsToTmp(result.tool, result.events); err != nil {
			errs = append(errs, err)
		}
		events = append(events, result.events...)
	}
	return events, errs
}

func (o *Orchestrator) appendStageEventsToTmp(tool string, events []Event) error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" || len(events) == 0 {
		return nil
	}

	if err := os.MkdirAll(o.config.TmpResultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create tmp results dir %s: %w", o.config.TmpResultsDir, err)
	}

	safeTool := sanitizeFilePart(tool)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	for _, base := range tmpArtifactBases(tool) {
		jsonPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.jsonl", base))
		csvPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.csv", base))
		if err := appendEventsJSONL(jsonPath, safeTool, ts, events); err != nil {
			return err
		}
		if err := appendEventsCSV(csvPath, safeTool, ts, events); err != nil {
			return err
		}
	}
	return nil
}

func tmpArtifactBases(tool string) []string {
	canonical := sanitizeFilePart(tool)
	bases := []string{canonical}

	// Compatibility alias so users can look for crt.sh artifacts directly.
	if normalizeToolName(tool) == "crtsh" {
		bases = append(bases, "crt.sh")
	}
	return bases
}

func sanitizeFilePart(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "unknown_tool"
	}

	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}

	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown_tool"
	}
	return out
}

func appendEventsJSONL(path, tool, timestamp string, events []Event) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tmp JSON file %s: %w", path, err)
	}
	defer file.Close()

	bw := bufio.NewWriterSize(file, 64*1024)
	encoder := json.NewEncoder(bw)
	for _, ev := range events {
		record := struct {
			Timestamp  string            `json:"timestamp"`
			Tool       string            `json:"tool"`
			Target     string            `json:"target"`
			Source     string            `json:"source"`
			Type       string            `json:"type"`
			Properties map[string]string `json:"properties,omitempty"`
		}{
			Timestamp:  timestamp,
			Tool:       tool,
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
		}
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("failed to append JSON event to %s: %w", path, err)
		}
	}
	return bw.Flush()
}

func appendEventsCSV(path, tool, timestamp string, events []Event) error {
	writeHeader := false
	if info, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat tmp CSV file %s: %w", path, err)
		}
		writeHeader = true
	} else if info.Size() == 0 {
		writeHeader = true
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tmp CSV file %s: %w", path, err)
	}
	defer file.Close()

	bw := bufio.NewWriterSize(file, 64*1024)
	writer := csv.NewWriter(bw)
	if writeHeader {
		if err := writer.Write([]string{"timestamp", "tool", "target", "source", "type", "properties_json"}); err != nil {
			return fmt.Errorf("failed to write CSV header to %s: %w", path, err)
		}
	}

	for _, ev := range events {
		propsJSON, err := json.Marshal(ev.Properties)
		if err != nil {
			return fmt.Errorf("failed to serialize properties for CSV: %w", err)
		}
		if err := writer.Write([]string{timestamp, tool, ev.Target, ev.Source, ev.Type, string(propsJSON)}); err != nil {
			return fmt.Errorf("failed to append CSV event to %s: %w", path, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV file %s: %w", path, err)
	}
	return bw.Flush()
}

func extractTargets(events []Event) []string {
	targets := make([]string, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.Target) == "" {
			continue
		}
		targets = append(targets, event.Target)
	}
	return targets
}

func filterEventsInScope(scopeGuard *normalize.ScopeGuard, events []Event) []Event {
	if scopeGuard == nil || len(events) == 0 {
		return events
	}
	out := make([]Event, 0, len(events))
	for _, event := range events {
		if !scopeGuard.IsAllowed(event.Target) {
			continue
		}
		out = append(out, event)
	}
	return out
}

func extractLiveWebTargets(events []Event) []string {
	targets := make([]string, 0, len(events))
	for _, event := range events {
		if normalizeToolName(event.Source) != "httpx" {
			continue
		}
		target := strings.TrimSpace(event.Target)
		if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

func prepareTargetsForTool(toolName string, targets []string) []string {
	name := normalizeToolName(toolName)
	if name == "uro" {
		// uro is URL-focused; keep only fully-qualified web URLs.
		urls := make([]string, 0, len(targets))
		for _, target := range targets {
			t := strings.TrimSpace(strings.ToLower(target))
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
				urls = append(urls, target)
			}
		}
		return normalize.DeduplicateAndPreserveURLs(urls)
	}

	stage := GetToolStage(toolName)
	if stage <= 1 || name == "dnsx" || name == "naabu" || name == "shodan" {
		// Preprocessing, passive/DNS tools, port scanners, and host search engines
		// should receive host-like targets, not deep URL paths.
		return normalize.DeduplicateAndNormalize(targets)
	}

	if name == "ffuf" || name == "gobuster" || name == "feroxbuster" {
		// Brute-force directory fuzzers. Limit to unique directory paths.
		var dirTargets []string
		seenDirs := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			parsed, err := url.Parse(target)
			if err != nil || parsed.Host == "" {
				continue
			}
			// Root directory
			baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			if _, ok := seenDirs[baseURL]; !ok {
				seenDirs[baseURL] = struct{}{}
				dirTargets = append(dirTargets, baseURL)
			}
			// First-level subdirectories
			path := parsed.Path
			if path != "" && path != "/" {
				parts := strings.Split(path, "/")
				if len(parts) > 1 && parts[1] != "" {
					firstSeg := parts[1]
					if !strings.Contains(firstSeg, ".") {
						dirURL := fmt.Sprintf("%s://%s/%s", parsed.Scheme, parsed.Host, firstSeg)
						if _, ok := seenDirs[dirURL]; !ok {
							seenDirs[dirURL] = struct{}{}
							dirTargets = append(dirTargets, dirURL)
						}
					}
				}
			}
		}
		if len(dirTargets) > 10 {
			dirTargets = dirTargets[:10]
		}
		return dirTargets
	}

	if name == "dalfox" {
		// Parameterized XSS scanner. Only test URLs with parameters or fall back to base URL.
		var dalfoxTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			if !strings.Contains(target, "?") {
				continue
			}
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				dalfoxTargets = append(dalfoxTargets, target)
			}
		}
		if len(dalfoxTargets) == 0 {
			for _, target := range targets {
				if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
					continue
				}
				parsed, err := url.Parse(target)
				if err == nil && parsed.Host != "" {
					baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
					if _, ok := seen[baseURL]; !ok {
						seen[baseURL] = struct{}{}
						dalfoxTargets = append(dalfoxTargets, baseURL)
					}
				}
			}
		}
		if len(dalfoxTargets) > 20 {
			dalfoxTargets = dalfoxTargets[:20]
		}
		return dalfoxTargets
	}

	if name == "nuclei" {
		// Vulnerability scanner. Exclude static assets to prevent overhead.
		var nucleiTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			tLower := strings.ToLower(target)
			if strings.HasSuffix(tLower, ".png") || strings.HasSuffix(tLower, ".jpg") ||
				strings.HasSuffix(tLower, ".jpeg") || strings.HasSuffix(tLower, ".gif") ||
				strings.HasSuffix(tLower, ".css") || strings.HasSuffix(tLower, ".ico") ||
				strings.HasSuffix(tLower, ".woff") || strings.HasSuffix(tLower, ".woff2") ||
				strings.HasSuffix(tLower, ".ttf") || strings.HasSuffix(tLower, ".svg") ||
				strings.HasSuffix(tLower, ".map") {
				continue
			}
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				nucleiTargets = append(nucleiTargets, target)
			}
		}
		// Prioritize targets by heuristic score:
		// admin, api, upload, debug, login, config, console, setup, vuln
		priorityScore := func(t string) int {
			t = strings.ToLower(t)
			score := 0
			keywords := []string{"admin", "api", "upload", "debug", "login", "config", "console", "setup", "vulnerable", "vuln"}
			for _, kw := range keywords {
				if strings.Contains(t, kw) {
					score += 10
				}
			}
			if strings.Contains(t, "?") {
				score += 5
			}
			score += strings.Count(t, "/")
			return score
		}
		sort.SliceStable(nucleiTargets, func(i, j int) bool {
			return priorityScore(nucleiTargets[i]) > priorityScore(nucleiTargets[j])
		})
		if len(nucleiTargets) > 200 {
			slog.Warn("nuclei targets exceeded cap; truncating to 200 priority targets", "original_count", len(nucleiTargets))
			nucleiTargets = nucleiTargets[:200]
		}
		return nucleiTargets
	}

	return targets
}

func (o *Orchestrator) reportEvent(ev Event) {
	if o.scopeGuard != nil && !o.scopeGuard.IsAllowed(ev.Target) {
		return
	}
	if reporter, ok := o.config.Reporter.(eventReporter); ok {
		reporter.ReportEvent(ev.Source, ev.Target, ev.Type, ev.Properties)
	}
	slog.Info("Discovered "+ev.Type+": "+ev.Target, "tool", ev.Source)
}

func (o *Orchestrator) reportToolStatus(tool, status, detail string) {
	if reporter, ok := o.config.Reporter.(toolStatusReporter); ok {
		reporter.ReportToolStatus(tool, status, detail)
	}
}

func (o *Orchestrator) reportFailure(tool, detail string) {
	if reporter, ok := o.config.Reporter.(failureReporter); ok {
		reporter.ReportFailure(tool, detail)
	}
}

func (o *Orchestrator) dispatchToWorkerMesh(ctx context.Context, toolName string, targets []string, threads int) ([]Event, error) {
	jobID := fmt.Sprintf("job-%s-%d", toolName, time.Now().UnixNano())

	jobData, err := json.Marshal(map[string]interface{}{
		"id":        jobID,
		"tool_name": toolName,
		"targets":   targets,
		"threads":   threads,
	})
	if err != nil {
		return nil, err
	}

	o.bus.Publish(queue.Event{
		Target: "workers",
		Source: "orchestrator",
		Type:   "job.recon",
		Data:   jobData,
		Properties: map[string]string{
			"job_id":    jobID,
			"tool_name": toolName,
		},
	})

	// Wait for job.complete event and collect tool events
	sub := o.bus.Subscribe(toolName)
	completeSub := o.bus.Subscribe("job.complete")
	defer o.bus.Unsubscribe(sub)
	defer o.bus.Unsubscribe(completeSub)

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-timer.C:
			return events, fmt.Errorf("timeout waiting for worker mesh job %s", jobID)
		case ev := <-sub:
			// Tool specific events (e.g., from Nuclei, HTTPX)
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["job_id"] == jobID {
				if ev.Properties["status"] == "success" {
					return events, nil
				}
				return events, fmt.Errorf("worker mesh job failed: %s", ev.Properties["error"])
			}
		}
	}
}

func stageCapability(stage int) workers.CapabilityType {
	switch stage {
	case 1:
		return workers.CapSubdomainEnum
	case 2:
		return workers.CapPortScan
	case 3:
		return workers.CapBrowserRecon
	case 4:
		return workers.CapJSDiff
	default:
		return ""
	}
}

func (o *Orchestrator) dispatchStageTaskToWorkerMesh(ctx context.Context, stage int, capability workers.CapabilityType, targets []string) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	completeSub := o.bus.Subscribe("task.complete")
	eventSub := o.bus.Subscribe("event.>")
	defer o.bus.Unsubscribe(completeSub)
	defer o.bus.Unsubscribe(eventSub)

	taskSession := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
	pending := len(targets)

	for _, target := range targets {
		taskID := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
		spanID := telemetry.GetSpanID(ctx)
		payload := map[string]interface{}{}
		if spanID != "" {
			payload["_trace_parent_id"] = spanID
		}
		taskPayload, err := json.Marshal(workers.Task{
			ID:        taskID,
			Type:      capability,
			Target:    target,
			Payload:   payload,
			SessionID: taskSession,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal stage task: %w", err)
		}

		o.bus.Publish(queue.Event{
			Target: target,
			Source: "orchestrator",
			Type:   fmt.Sprintf("task.%s", capability),
			Data:   taskPayload,
			Properties: map[string]string{
				"task_id":    taskID,
				"task_type":  string(capability),
				"stage":      fmt.Sprintf("%d", stage),
				"session_id": taskSession,
			},
		})
	}

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for pending > 0 {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-timer.C:
			return events, fmt.Errorf("timeout waiting for stage %d completion", stage)
		case ev := <-eventSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			pending--
		}
	}

	return events, nil
}
