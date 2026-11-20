package main

import (
	"github.com/elazarl/goproxy"
)

// NewCertStorage returns the production certificate cache: single-flight
// issuance, LRU bounds, negative caching and per-target counters.
// See goproxy.NewCertCache and the goproxy.CertCacheOption set for tuning.
func NewCertStorage() *goproxy.CertCache {
	return goproxy.NewCertCache()
}
