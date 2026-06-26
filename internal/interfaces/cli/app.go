// Package cli provides CLI interface components
package cli

import (
	"time"

	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

func notifierConfigFrom(cfg config.NotifyConfig) utils.Config {
	return utils.Config{
		TelegramBotToken: cfg.TelegramBotToken,
		TelegramChatID:   cfg.TelegramChatID,
		DiscordWebhook:   cfg.DiscordWebhook,
		SlackWebhook:     cfg.SlackWebhook,
	}
}

// Options holds all runtime parameters for the BBPTS engine.
type Options struct {
	InputPath         string
	Tools             string
	OutputPath        string
	SummaryPath       string
	ObsidianDir       string
	ObsidianName      string
	Timeout           time.Duration
	Debug             bool
	Threads           int
	ConfigPath        string
	RateLimit         int
	Scope             string
	DiffOnly          bool
	RulesPath         string
	SkipRules         bool
	EnableFingerprint bool
	EnableFleet       bool
	EnableDashboard   bool
	DashboardPort     int
	ReportH1          string
	ReportBC          string
	ExportBurp        string
	CronInterval      int
	LowResource       bool
	UseTUI            bool
	RunDoctor         bool
	Preset            string
	Profile           string
	Mode              string
	EvidencePath      string
	EvidenceTopN      int
	LightMode         bool
	FullMode          bool
	RunWorker         bool
	Submit            bool
	TLSEnabled        bool
	TLSCertFile       string
	TLSKeyFile        string
	WebEnder          string
	ShowVersion       bool
	EnableMetrics     bool
	MetricsPort       int
	LogFilePath       string
	Headers           string
	Cookie            string
	MaxCPUPercent     int
	MaxCPUCores       int
	MaxMemoryMB       int
	GCPercent         int
	Resume            bool
	JSONOutput        bool
	AutoUpdate        bool
	ExcludeTools      string
	BatchSize         int
	LogLevel          string
	ReportTemplate    string
	CI                bool
	CIFailOn          string
	ScopeFile         string
	PassiveMode       bool
	DryRun            bool
	ExploitSQLI       bool
	ForceHTTP1        bool
	AssetStore        string
	DraftReport       bool
	MinimumConfidence int
	FPThreshold       int
	IncludeFP         bool
	FPAudit           bool
	H1                string
	BC                string
	Program           string
	RefreshProgram    bool
	AITriage          bool
	AITriageThreshold int
	AITriageProvider  string
	AITriageModel     string
	AITriageURL       string
}
