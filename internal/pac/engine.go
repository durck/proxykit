// Package pac implements optional PAC/WPAD proxy auto-configuration: it
// fetches and evaluates a FindProxyForURL(url, host) script and performs
// active DNS-WPAD discovery. The goja-backed evaluator is compiled only
// with -tags proxykit_pac (see eval.go); the default build links a stub
// (stub.go) that reports the feature is unavailable, so the JS engine
// never enters the dependency graph.
//
// The package is a leaf: it depends only on the standard library (plus
// goja under the build tag) and never imports the parent proxykit
// package. The host application drives it through NewEngine, Supported,
// FetchScript and CandidateWPADURLs, and assembles dialers from the
// results itself.
package pac

import "context"

// Engine evaluates a compiled PAC (Proxy Auto-Config) script's
// FindProxyForURL for a destination. It is implemented only in binaries
// built with -tags proxykit_pac; the default build wires a stub whose
// constructor reports errors.ErrUnsupported.
type Engine interface {
	// FindProxy runs FindProxyForURL(rawURL, host) and returns its raw
	// result string, e.g. "PROXY proxy:8080; DIRECT".
	FindProxy(ctx context.Context, rawURL, host string) (string, error)

	// Close releases any resources (e.g. the JS runtime watchdog).
	Close()
}

// NewEngine compiles a PAC script into an Engine. It is assigned at init
// time by eval.go (//go:build proxykit_pac) or stub.go
// (//go:build !proxykit_pac), so it is never nil after package init.
var NewEngine func(script string) (Engine, error)

// Supported is set true by eval.go's init under -tags proxykit_pac. The
// default build leaves it false, so the caller degrades a configured PAC
// source to the static path with a warning rather than silently doing
// nothing.
var Supported bool
