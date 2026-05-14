package network

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CircuitState represents the current state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the circuit is healthy and requests flow normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the circuit has tripped and requests are rejected immediately.
	CircuitOpen
	// CircuitHalfOpen means the circuit is testing whether the downstream has recovered.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when a request is rejected by an open circuit.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreakerConfig configures the circuit breaker thresholds.
type CircuitBreakerConfig struct {
	// MaxFailures is the number of consecutive failures before the circuit opens.
	MaxFailures int
	// ResetTimeout is how long to wait in the open state before allowing a probe request.
	ResetTimeout time.Duration
	// HalfOpenMaxRequests is the max number of probe requests in the half-open state.
	HalfOpenMaxRequests int
	// SuccessThreshold is how many successes in half-open are needed to close the circuit.
	SuccessThreshold int
}

// DefaultCircuitBreakerConfig returns sensible defaults for recon tool execution.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:         5,
		ResetTimeout:        30 * time.Second,
		HalfOpenMaxRequests: 3,
		SuccessThreshold:    2,
	}
}

// CircuitBreaker implements the circuit breaker pattern for protecting against
// cascading failures when external tools or services are unavailable.
type CircuitBreaker struct {
	name   string
	config CircuitBreakerConfig

	state              CircuitState
	failures           int
	successes          int
	halfOpenRequests   int
	lastFailureTime    time.Time
	lastStateChange    time.Time

	mu sync.RWMutex

	// Callbacks for observability
	onStateChange func(name string, from, to CircuitState)
}

// NewCircuitBreaker creates a new circuit breaker with the given name and config.
func NewCircuitBreaker(name string, config CircuitBreakerConfig) *CircuitBreaker {
	if config.MaxFailures <= 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout <= 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.HalfOpenMaxRequests <= 0 {
		config.HalfOpenMaxRequests = 3
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}

	return &CircuitBreaker{
		name:            name,
		config:          config,
		state:           CircuitClosed,
		lastStateChange: time.Now(),
	}
}

// SetOnStateChange registers a callback for state transitions.
func (cb *CircuitBreaker) SetOnStateChange(fn func(name string, from, to CircuitState)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

// Allow checks if the circuit breaker allows a request to proceed.
// Returns true if allowed, false if the circuit is open.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if enough time has passed to move to half-open
		if time.Since(cb.lastStateChange) >= cb.config.ResetTimeout {
			cb.transitionTo(CircuitHalfOpen)
			cb.halfOpenRequests++
			return true
		}
		return false

	case CircuitHalfOpen:
		if cb.halfOpenRequests < cb.config.HalfOpenMaxRequests {
			cb.halfOpenRequests++
			return true
		}
		return false

	default:
		return false
	}
}

// RecordSuccess records a successful execution. In half-open state, enough
// successes will close the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		cb.failures = 0 // reset on success
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}
	}
}

// RecordFailure records a failed execution. In closed state, enough failures
// will trip the circuit open.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failures++
		if cb.failures >= cb.config.MaxFailures {
			cb.transitionTo(CircuitOpen)
		}
	case CircuitHalfOpen:
		// Any failure in half-open goes back to open
		cb.transitionTo(CircuitOpen)
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns circuit breaker statistics.
func (cb *CircuitBreaker) Stats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return map[string]interface{}{
		"name":              cb.name,
		"state":             cb.state.String(),
		"failures":          cb.failures,
		"successes":         cb.successes,
		"last_failure_time": cb.lastFailureTime,
		"last_state_change": cb.lastStateChange,
	}
}

// transitionTo changes circuit state. Must be called with lock held.
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = time.Now()

	// Reset counters for the new state
	switch newState {
	case CircuitClosed:
		cb.failures = 0
		cb.successes = 0
		cb.halfOpenRequests = 0
	case CircuitOpen:
		cb.successes = 0
		cb.halfOpenRequests = 0
	case CircuitHalfOpen:
		cb.successes = 0
		cb.halfOpenRequests = 0
	}

	slog.Info("Circuit breaker state changed",
		"name", cb.name,
		"from", oldState.String(),
		"to", newState.String(),
	)

	if cb.onStateChange != nil {
		go cb.onStateChange(cb.name, oldState, newState)
	}
}

// CircuitBreakerRegistry manages circuit breakers for multiple tools.
type CircuitBreakerRegistry struct {
	breakers map[string]*CircuitBreaker
	config   CircuitBreakerConfig
	mu       sync.RWMutex
}

// NewCircuitBreakerRegistry creates a registry with a default config for new breakers.
func NewCircuitBreakerRegistry(config CircuitBreakerConfig) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
	}
}

// Get returns or creates a circuit breaker for the named tool.
func (r *CircuitBreakerRegistry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	if cb, ok := r.breakers[name]; ok {
		r.mu.RUnlock()
		return cb
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, ok := r.breakers[name]; ok {
		return cb
	}

	cb := NewCircuitBreaker(name, r.config)
	r.breakers[name] = cb
	return cb
}

// AllStats returns stats for all registered circuit breakers.
func (r *CircuitBreakerRegistry) AllStats() map[string]map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]map[string]interface{}, len(r.breakers))
	for name, cb := range r.breakers {
		stats[name] = cb.Stats()
	}
	return stats
}

// Execute runs the given function through a circuit breaker, returning an error
// if the circuit is open.
func Execute(cb *CircuitBreaker, fn func() error) error {
	if !cb.Allow() {
		return fmt.Errorf("%w: tool %s", ErrCircuitOpen, cb.name)
	}

	err := fn()
	if err != nil {
		cb.RecordFailure()
		return err
	}

	cb.RecordSuccess()
	return nil
}
