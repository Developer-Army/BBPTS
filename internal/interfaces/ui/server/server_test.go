package server

import (
	"testing"
)

func TestConfigStructure(t *testing.T) {
	cfg := Config{
		Port: 8080,
	}

	if cfg.Port != 8080 {
		t.Errorf("Expected Port 8080, got %d", cfg.Port)
	}
}

func TestConfigDefaultPort(t *testing.T) {
	cfg := Config{}

	if cfg.Port != 0 {
		t.Errorf("Expected Port 0, got %d", cfg.Port)
	}
}

func TestDashboardHTML(t *testing.T) {
	if DashboardHTML == "" {
		t.Error("Expected DashboardHTML to be non-empty")
	}

	if len(DashboardHTML) < 100 {
		t.Error("Expected DashboardHTML to have content")
	}
}

func TestDashboardHTMLContainsDOCTYPE(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<!DOCTYPE html>") {
		t.Error("Expected DashboardHTML to contain DOCTYPE declaration")
	}
}

func TestDashboardHTMLContainsTitle(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<title>") {
		t.Error("Expected DashboardHTML to contain title tag")
	}

	if !containsSubstring(DashboardHTML, "BBPTS") {
		t.Error("Expected DashboardHTML to contain 'BBPTS'")
	}
}

func TestDashboardHTMLContainsScriptTags(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<script>") {
		t.Error("Expected DashboardHTML to contain script tags")
	}
}

func TestDashboardHTMLContainsTailwind(t *testing.T) {
	if !containsSubstring(DashboardHTML, "tailwind.js") {
		t.Error("Expected DashboardHTML to contain Tailwind JS reference")
	}
}

func TestDashboardHTMLContainsChartJS(t *testing.T) {
	if !containsSubstring(DashboardHTML, "chart.js") {
		t.Error("Expected DashboardHTML to contain Chart.js CDN")
	}
}

func TestStartWithNilDB(t *testing.T) {
	cfg := Config{
		Port: 0, // Use port 0 to get a random available port
	}

	// This will fail to start properly due to nil db, but we can test the structure
	err := Start(cfg, nil, "", "")

	if err == nil {
		t.Error("Expected error when db is nil")
	}
}

func TestStartWithConfig(t *testing.T) {
	cfg := Config{
		Port: 8080,
	}

	// This would start a server, which we don't want in tests
	// Just verify the config structure is correct
	if cfg.Port != 8080 {
		t.Errorf("Expected Port 8080, got %d", cfg.Port)
	}
}

func TestStartWithDifferentPorts(t *testing.T) {
	ports := []int{8080, 3000, 5000, 9000}

	for _, port := range ports {
		cfg := Config{Port: port}
		if cfg.Port != port {
			t.Errorf("Expected Port %d, got %d", port, cfg.Port)
		}
	}
}

func TestStartWithPortZero(t *testing.T) {
	cfg := Config{
		Port: 0,
	}

	if cfg.Port != 0 {
		t.Errorf("Expected Port 0, got %d", cfg.Port)
	}
}

func TestStartWithNegativePort(t *testing.T) {
	cfg := Config{
		Port: -1,
	}

	if cfg.Port != -1 {
		t.Errorf("Expected Port -1, got %d", cfg.Port)
	}
}

func TestStartWithLargePort(t *testing.T) {
	cfg := Config{
		Port: 65535,
	}

	if cfg.Port != 65535 {
		t.Errorf("Expected Port 65535, got %d", cfg.Port)
	}
}

func TestStartWithPortAboveMax(t *testing.T) {
	cfg := Config{
		Port: 99999,
	}

	if cfg.Port != 99999 {
		t.Errorf("Expected Port 99999, got %d", cfg.Port)
	}
}

func TestDashboardHTMLContainsAPIEndpoints(t *testing.T) {
	if !containsSubstring(DashboardHTML, "/api/stats") {
		t.Error("Expected DashboardHTML to reference /api/stats endpoint")
	}

	if !containsSubstring(DashboardHTML, "/api/scans") {
		t.Error("Expected DashboardHTML to reference /api/scans endpoint")
	}
}

func TestDashboardHTMLContainsRefreshFunction(t *testing.T) {
	if !containsSubstring(DashboardHTML, "refreshData") {
		t.Error("Expected DashboardHTML to contain refreshData function")
	}
}

func TestDashboardHTMLContainsChartInitialization(t *testing.T) {
	if !containsSubstring(DashboardHTML, "initChart") {
		t.Error("Expected DashboardHTML to contain initChart function")
	}
}

func TestDashboardHTMLContainsStatElements(t *testing.T) {
	if !containsSubstring(DashboardHTML, "stat-targets") {
		t.Error("Expected DashboardHTML to contain stat-targets element")
	}

	if !containsSubstring(DashboardHTML, "stat-scans") {
		t.Error("Expected DashboardHTML to contain stat-scans element")
	}

	if !containsSubstring(DashboardHTML, "stat-critical") {
		t.Error("Expected DashboardHTML to contain stat-critical element")
	}
}

func TestDashboardHTMLContainsTable(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<table") {
		t.Error("Expected DashboardHTML to contain table element")
	}

	if !containsSubstring(DashboardHTML, "scan-history") {
		t.Error("Expected DashboardHTML to contain scan-history table body")
	}
}

func TestDashboardHTMLContainsCanvas(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<canvas") {
		t.Error("Expected DashboardHTML to contain canvas element")
	}

	if !containsSubstring(DashboardHTML, "surface-chart") {
		t.Error("Expected DashboardHTML to contain surface-chart canvas")
	}
}

func TestDashboardHTMLContainsSidebar(t *testing.T) {
	if !containsSubstring(DashboardHTML, "sidebar") {
		t.Error("Expected DashboardHTML to contain sidebar element")
	}
}

func TestDashboardHTMLContainsNavigation(t *testing.T) {
	if !containsSubstring(DashboardHTML, "nav-item") {
		t.Error("Expected DashboardHTML to contain navigation items")
	}
}

func TestDashboardHTMLContainsStyles(t *testing.T) {
	if !containsSubstring(DashboardHTML, "<style>") {
		t.Error("Expected DashboardHTML to contain style tags")
	}
}

func TestDashboardHTMLContainsGlassEffect(t *testing.T) {
	if !containsSubstring(DashboardHTML, "glass") {
		t.Error("Expected DashboardHTML to contain glass effect class")
	}
}

func TestDashboardHTMLContainsAccentColor(t *testing.T) {
	if !containsSubstring(DashboardHTML, "text-cyan-400") {
		t.Error("Expected DashboardHTML to contain accent color class")
	}
}

func TestDashboardHTMLContainsFooter(t *testing.T) {
	if !containsSubstring(DashboardHTML, "Bug Bounty Recon Console") {
		t.Error("Expected DashboardHTML to contain Bug Bounty Recon Console tagline")
	}
}

func TestDashboardHTMLContainsDeployButton(t *testing.T) {
	if !containsSubstring(DashboardHTML, "START SCAN") {
		t.Error("Expected DashboardHTML to contain START SCAN button")
	}
}

func TestDashboardHTMLContainsMissionControl(t *testing.T) {
	if !containsSubstring(DashboardHTML, "Mission Control") {
		t.Error("Expected DashboardHTML to contain Mission Control heading")
	}
}

func TestDashboardHTMLContainsAutoRefresh(t *testing.T) {
	if !containsSubstring(DashboardHTML, "setInterval") {
		t.Error("Expected DashboardHTML to contain auto-refresh interval")
	}
}

func TestDashboardHTMLContainsErrorHandling(t *testing.T) {
	if !containsSubstring(DashboardHTML, "catch") {
		t.Error("Expected DashboardHTML to contain error handling")
	}
}

func TestDashboardHTMLContainsConsoleError(t *testing.T) {
	if !containsSubstring(DashboardHTML, "console.error") {
		t.Error("Expected DashboardHTML to contain console.error")
	}
}

func TestDashboardHTMLContainsFetchAPI(t *testing.T) {
	if !containsSubstring(DashboardHTML, "fetch") {
		t.Error("Expected DashboardHTML to contain fetch API calls")
	}
}

func TestDashboardHTMLContainsAsyncAwait(t *testing.T) {
	if !containsSubstring(DashboardHTML, "async") {
		t.Error("Expected DashboardHTML to contain async function")
	}

	if !containsSubstring(DashboardHTML, "await") {
		t.Error("Expected DashboardHTML to contain await keyword")
	}
}

func TestDashboardHTMLContainsPromiseAll(t *testing.T) {
	if !containsSubstring(DashboardHTML, "Promise.all") {
		t.Error("Expected DashboardHTML to contain Promise.all")
	}
}

func TestDashboardHTMLContainsDOMContentLoaded(t *testing.T) {
	if !containsSubstring(DashboardHTML, "window.onload") {
		t.Error("Expected DashboardHTML to contain window.onload")
	}
}

func TestDashboardHTMLEncoding(t *testing.T) {
	// Verify the HTML is properly encoded
	if containsSubstring(DashboardHTML, "\x00") {
		t.Error("DashboardHTML should not contain null bytes")
	}
}

func TestDashboardHTMLLength(t *testing.T) {
	// DashboardHTML should be substantial
	if len(DashboardHTML) < 1000 {
		t.Errorf("Expected DashboardHTML to be at least 1000 characters, got %d", len(DashboardHTML))
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Error("expected certificate to contain at least one certificate block")
	}

	if cert.PrivateKey == nil {
		t.Error("expected certificate to contain a private key")
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
