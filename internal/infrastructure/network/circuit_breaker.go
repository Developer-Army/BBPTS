package network

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type CircuitState int

const (
	CircuitClosed CircuitState = iota

	CircuitOpen

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

var ErrCircuitOpen = errors.New("circuit breaker is open")

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

func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:         5,
		ResetTimeout:        30 * time.Second,
		HalfOpenMaxRequests: 3,
		SuccessThreshold:    2,
	}
}

type CircuitBreaker struct {
	name   string
	config CircuitBreakerConfig

	state            CircuitState
	failures         int
	successes        int
	halfOpenRequests int
	lastFailureTime  time.Time
	lastStateChange  time.Time

	mu sync.RWMutex

	// Callbacks for observability
	onStateChange func(name string, from, to CircuitState)
}

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

func (cb *CircuitBreaker) SetOnStateChange(fn func(name string, from, to CircuitState)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:

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

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		cb.failures = 0
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}
	}
}

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

		cb.transitionTo(CircuitOpen)
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

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

func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = time.Now()

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

type CircuitBreakerRegistry struct {
	breakers map[string]*CircuitBreaker
	config   CircuitBreakerConfig
	mu       sync.RWMutex
}

func NewCircuitBreakerRegistry(config CircuitBreakerConfig) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
	}
}

func (r *CircuitBreakerRegistry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	if cb, ok := r.breakers[name]; ok {
		r.mu.RUnlock()
		return cb
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if cb, ok := r.breakers[name]; ok {
		return cb
	}

	cb := NewCircuitBreaker(name, r.config)
	r.breakers[name] = cb
	return cb
}

func (r *CircuitBreakerRegistry) AllStats() map[string]map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]map[string]interface{}, len(r.breakers))
	for name, cb := range r.breakers {
		stats[name] = cb.Stats()
	}
	return stats
}

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
