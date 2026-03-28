package gateway

import (
	"expvar"

	"github.com/LCGant/role-gateway/gateway/internal/config"
	"github.com/LCGant/role-gateway/libs/common/circuit"
)

type breakerMetric struct {
	state *expvar.String
	trips *expvar.Int
}

func newBreaker(cfg config.Config) *circuit.Breaker {
	if !cfg.BreakerEnabled {
		return nil
	}
	return circuit.New(circuit.Options{
		FailureThreshold: cfg.BreakerFailures,
		ResetTimeout:     cfg.BreakerReset,
		HalfOpenMax:      cfg.BreakerHalfOpen,
	})
}

func newBreakerMetric(name string, br *circuit.Breaker) *breakerMetric {
	if br == nil {
		return nil
	}
	metric := &breakerMetric{
		state: expvar.NewString("breaker." + name + ".state"),
		trips: expvar.NewInt("breaker." + name + ".trips"),
	}
	metric.state.Set("closed")
	return metric
}

func updateBreakerMetric(rt *route) {
	if rt == nil || rt.metric == nil || rt.breaker == nil {
		return
	}
	state := rt.breaker.State()
	rt.metric.state.Set(stateToString(state))
	if state == circuit.Open {
		rt.metric.trips.Add(1)
	}
}

func stateToString(s circuit.State) string {
	switch s {
	case circuit.Closed:
		return "closed"
	case circuit.Open:
		return "open"
	case circuit.HalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}
