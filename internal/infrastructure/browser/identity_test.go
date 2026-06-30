package browser

import (
	"testing"
)

func TestNewIdentityPool(t *testing.T) {
	pool := NewIdentityPool()

	if pool == nil {
		t.Fatal("NewIdentityPool returned nil")
	}

	if pool.Identities == nil {
		t.Error("Expected Identities map to be initialized")
	}
}

func TestGetOrCreate(t *testing.T) {
	pool := NewIdentityPool()

	id1 := pool.GetOrCreate("session-1")
	if id1 == nil {
		t.Fatal("GetOrCreate returned nil")
	}

	if id1.ID == "" {
		t.Error("Expected ID to be set")
	}

	if id1.UserAgent == "" {
		t.Error("Expected UserAgent to be set")
	}

	if id1.BehavioralTrust != 100 {
		t.Errorf("Expected BehavioralTrust 100, got %d", id1.BehavioralTrust)
	}

	if id1.Burned {
		t.Error("Expected Burned to be false for new identity")
	}

	id2 := pool.GetOrCreate("session-1")
	if id2.ID != id1.ID {
		t.Error("Expected same identity for same session ID")
	}

	id3 := pool.GetOrCreate("session-2")
	if id3.ID == id1.ID {
		t.Error("Expected different identity for different session ID")
	}
}

func TestGetOrCreateBurnedIdentity(t *testing.T) {
	pool := NewIdentityPool()

	id1 := pool.GetOrCreate("session-1")

	id1.Burned = true

	id2 := pool.GetOrCreate("session-1")
	if id2.ID == id1.ID {
		t.Error("Expected new identity when previous is burned")
	}

	if id2.Burned {
		t.Error("Expected new identity to not be burned")
	}
}

func TestReportChallenge(t *testing.T) {
	pool := NewIdentityPool()

	id := pool.GetOrCreate("session-1")

	initialTrust := id.BehavioralTrust
	initialCaptchas := id.CaptchasEncountered

	pool.ReportChallenge("session-1")

	if id.CaptchasEncountered != initialCaptchas+1 {
		t.Errorf("Expected CaptchasEncountered %d, got %d", initialCaptchas+1, id.CaptchasEncountered)
	}

	if id.BehavioralTrust != initialTrust-20 {
		t.Errorf("Expected BehavioralTrust %d, got %d", initialTrust-20, id.BehavioralTrust)
	}

	pool.ReportChallenge("session-1")

	if id.CaptchasEncountered != initialCaptchas+2 {
		t.Errorf("Expected CaptchasEncountered %d, got %d", initialCaptchas+2, id.CaptchasEncountered)
	}

	pool.ReportChallenge("session-1")

	if id.CaptchasEncountered != initialCaptchas+3 {
		t.Errorf("Expected CaptchasEncountered %d, got %d", initialCaptchas+3, id.CaptchasEncountered)
	}

	if !id.Burned {
		t.Error("Expected identity to be burned after 3 challenges")
	}
}

func TestReportChallengeBurnsOnLowTrust(t *testing.T) {
	pool := NewIdentityPool()

	id := pool.GetOrCreate("session-1")

	id.BehavioralTrust = 10

	pool.ReportChallenge("session-1")

	if !id.Burned {
		t.Error("Expected identity to be burned when trust goes below 0")
	}
}

func TestReportChallengeNonExistentSession(t *testing.T) {
	pool := NewIdentityPool()

	pool.ReportChallenge("non-existent")
}

func TestGenerateCoherentIdentity(t *testing.T) {
	id := generateCoherentIdentity("test-seed")

	if id == nil {
		t.Fatal("generateCoherentIdentity returned nil")
	}

	if id.ID == "" {
		t.Error("Expected ID to be set")
	}

	if len(id.ID) != 16 {
		t.Errorf("Expected ID length 16, got %d", len(id.ID))
	}

	if id.UserAgent == "" {
		t.Error("Expected UserAgent to be set")
	}

	if id.ViewportWidth != 1920 {
		t.Errorf("Expected ViewportWidth 1920, got %d", id.ViewportWidth)
	}

	if id.ViewportHeight != 1080 {
		t.Errorf("Expected ViewportHeight 1080, got %d", id.ViewportHeight)
	}

	if id.DeviceScaleFactor != 1.0 {
		t.Errorf("Expected DeviceScaleFactor 1.0, got %f", id.DeviceScaleFactor)
	}

	if id.TimezoneID != "America/New_York" {
		t.Errorf("Expected TimezoneID 'America/New_York', got '%s'", id.TimezoneID)
	}

	if id.Locale != "en-US" {
		t.Errorf("Expected Locale 'en-US', got '%s'", id.Locale)
	}

	if id.BehavioralTrust != 100 {
		t.Errorf("Expected BehavioralTrust 100, got %d", id.BehavioralTrust)
	}

	if id.Burned {
		t.Error("Expected Burned to be false")
	}
}

func TestGenerateCoherentIdentityUniqueIDs(t *testing.T) {
	id1 := generateCoherentIdentity("seed-1")
	id2 := generateCoherentIdentity("seed-2")

	if id1.ID == id2.ID {
		t.Error("Expected different IDs for different seeds")
	}
}

func TestIdentityDefaults(t *testing.T) {
	id := &Identity{
		ID:                "test-id",
		UserAgent:         "Mozilla/5.0",
		ViewportWidth:     1920,
		ViewportHeight:    1080,
		DeviceScaleFactor: 1.0,
		TimezoneID:        "America/New_York",
		Locale:            "en-US",
		BehavioralTrust:   100,
	}

	if id.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got %s", id.ID)
	}
	if id.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected UserAgent 'Mozilla/5.0', got %s", id.UserAgent)
	}
	if id.ViewportWidth != 1920 {
		t.Errorf("Expected ViewportWidth 1920, got %d", id.ViewportWidth)
	}
	if id.ViewportHeight != 1080 {
		t.Errorf("Expected ViewportHeight 1080, got %d", id.ViewportHeight)
	}
	if id.DeviceScaleFactor != 1.0 {
		t.Errorf("Expected DeviceScaleFactor 1.0, got %f", id.DeviceScaleFactor)
	}
	if id.TimezoneID != "America/New_York" {
		t.Errorf("Expected TimezoneID 'America/New_York', got %s", id.TimezoneID)
	}
	if id.Locale != "en-US" {
		t.Errorf("Expected Locale 'en-US', got %s", id.Locale)
	}
	if id.BehavioralTrust != 100 {
		t.Errorf("Expected BehavioralTrust 100, got %d", id.BehavioralTrust)
	}

	if id.HasTouch {
		t.Error("Expected HasTouch to be false by default")
	}

	if id.IsMobile {
		t.Error("Expected IsMobile to be false by default")
	}

	if id.Geolocation != nil {
		t.Error("Expected Geolocation to be nil by default")
	}

	if id.TLSFingerprint != "" {
		t.Error("Expected TLSFingerprint to be empty by default")
	}

	if id.CaptchasEncountered != 0 {
		t.Error("Expected CaptchasEncountered to be 0 by default")
	}

	if id.Burned {
		t.Error("Expected Burned to be false by default")
	}
}

func TestGeolocation(t *testing.T) {
	geo := &Geolocation{
		Latitude:  40.7128,
		Longitude: -74.0060,
	}

	if geo.Latitude != 40.7128 {
		t.Errorf("Expected Latitude 40.7128, got %f", geo.Latitude)
	}

	if geo.Longitude != -74.0060 {
		t.Errorf("Expected Longitude -74.0060, got %f", geo.Longitude)
	}
}
