package quota

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type QuotaUsage struct {
	ShodanCalls int       `json:"shodan_calls"`
	ChaosCalls  int       `json:"chaos_calls"`
	GitHubCalls int       `json:"github_calls"`
	LastReset   time.Time `json:"last_reset"`
}

type QuotaGuard struct {
	stateDir string
	filePath string
	mu       sync.Mutex
	usage    QuotaUsage
}

func NewQuotaGuard(stateDir string) *QuotaGuard {
	filePath := filepath.Join(stateDir, "quota_usage.json")
	q := &QuotaGuard{
		stateDir: stateDir,
		filePath: filePath,
	}
	q.Load()
	return q
}

func (q *QuotaGuard) Load() {
	q.mu.Lock()
	defer q.mu.Unlock()
	data, err := os.ReadFile(q.filePath)
	if err == nil {
		var usage QuotaUsage
		if err := json.Unmarshal(data, &usage); err == nil {
			q.usage = usage
		}
	}
	now := time.Now()
	if q.usage.LastReset.IsZero() || now.Sub(q.usage.LastReset) > 30*24*time.Hour {
		q.usage.ShodanCalls = 0
		q.usage.ChaosCalls = 0
		q.usage.GitHubCalls = 0
		q.usage.LastReset = now
		q.saveInternal()
	}
}

func (q *QuotaGuard) Increment(provider string) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	switch provider {
	case "shodan":
		q.usage.ShodanCalls++
	case "chaos":
		q.usage.ChaosCalls++
	case "github":
		q.usage.GitHubCalls++
	}
	q.saveInternal()

	switch provider {
	case "shodan":
		return q.usage.ShodanCalls
	case "chaos":
		return q.usage.ChaosCalls
	case "github":
		return q.usage.GitHubCalls
	default:
		return 0
	}
}

func (q *QuotaGuard) GetUsage() QuotaUsage {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.usage
}

func (q *QuotaGuard) saveInternal() {
	if q.stateDir != "" {
		_ = os.MkdirAll(q.stateDir, 0700)
	}
	data, err := json.MarshalIndent(q.usage, "", "  ")
	if err == nil {
		_ = os.WriteFile(q.filePath, data, 0600)
	}
}
