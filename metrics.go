package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the whole observability surface, matching docs/api.md exactly — that
// document is the contract; these names are its implementation. Registered against a private
// registry rather than the global default, so tests can create a fresh Metrics per test without
// a "duplicate metrics collector registration" panic.
type Metrics struct {
	registry *prometheus.Registry

	PushTotal        *prometheus.CounterVec
	RegisterTotal    *prometheus.CounterVec
	RateLimitedTotal *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	m := &Metrics{registry: prometheus.NewRegistry()}

	m.PushTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pushrelay_push_total",
		Help: "Push attempts through /v1/push, by app, type and result.",
	}, []string{"app", "type", "result"})

	m.RegisterTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pushrelay_register_total",
		Help: "Calls to /v1/register, by app and result.",
	}, []string{"app", "result"})

	m.RateLimitedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pushrelay_ratelimited_total",
		Help: "Requests rejected with 429, by app and which scope's bucket tripped.",
	}, []string{"app", "scope"})

	m.registry.MustRegister(m.PushTotal, m.RegisterTotal, m.RateLimitedTotal)
	return m
}
