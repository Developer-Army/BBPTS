package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"sync"
	"time"
)

// Identity represents a coherent browser fingerprint and TLS profile to evade WAFs.
type Identity struct {
	ID                  string
	UserAgent           string
	ViewportWidth       int
	ViewportHeight      int
	DeviceScaleFactor   float64
	HasTouch            bool
	IsMobile            bool
	TimezoneID          string
	Locale              string
	Geolocation         *Geolocation
	TLSFingerprint      string
	BehavioralTrust     int // Score representing how "human" the session is acting
	CaptchasEncountered int
	Burned              bool // True if blocked by WAF too many times
}

type Geolocation struct {
	Latitude  float64
	Longitude float64
}

// IdentityPool manages a fleet of realistic browser identities.
type IdentityPool struct {
	mu         sync.RWMutex
	Identities map[string]*Identity
}

// NewIdentityPool initializes a pool of distinct browser profiles.
func NewIdentityPool() *IdentityPool {
	return &IdentityPool{
		Identities: make(map[string]*Identity),
	}
}

// GetOrCreate Identity returns an existing identity or generates a new coherent one.
func (p *IdentityPool) GetOrCreate(sessionID string) *Identity {
	p.mu.Lock()
	defer p.mu.Unlock()

	if id, exists := p.Identities[sessionID]; exists && !id.Burned {
		return id
	}

	// Generate a new realistic identity
	newID := generateCoherentIdentity(sessionID)
	p.Identities[sessionID] = newID
	return newID
}

// ReportChallenge decreases the trust score of an identity if it encounters a CAPTCHA.
func (p *IdentityPool) ReportChallenge(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if id, exists := p.Identities[sessionID]; exists {
		id.CaptchasEncountered++
		id.BehavioralTrust -= 20
		if id.CaptchasEncountered > 3 || id.BehavioralTrust < 0 {
			id.Burned = true
		}
	}
}

func generateCoherentIdentity(seed string) *Identity {
	hash := sha256.Sum256([]byte(seed + time.Now().String()))
	hashStr := hex.EncodeToString(hash[:])

	// Seed PRNG locally for deterministic profile attributes based on hash
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Simplistic coherent generation. In a real stealth platform, these are pulled from a known-good database.
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	}

	return &Identity{
		ID:                hashStr[:16],
		UserAgent:         userAgents[rng.Intn(len(userAgents))],
		ViewportWidth:     1920,
		ViewportHeight:    1080,
		DeviceScaleFactor: 1.0,
		TimezoneID:        "America/New_York",
		Locale:            "en-US",
		BehavioralTrust:   100,
	}
}
