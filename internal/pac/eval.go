//go:build proxykit_pac

package pac

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// pacEvalTimeout caps a single FindProxyForURL evaluation, guarding
// against a runaway or malicious PAC script.
const pacEvalTimeout = 5 * time.Second

var errPACTimeout = errors.New("proxykit: PAC evaluation timed out")

// This file is compiled only with -tags proxykit_pac. It wires NewEngine
// to the real goja-backed evaluator, pulling in the JS engine dependency.
// The default build uses stub.go instead.
func init() {
	Supported = true
	NewEngine = func(script string) (Engine, error) {
		return compilePAC(script, systemPACResolver{})
	}
}

// gojaPACEngine evaluates FindProxyForURL on a single goja.Runtime.
// goja.Runtime is NOT safe for concurrent use, so every evaluation is
// serialized by mu. The pure path is microsecond-fast; network helpers
// are independently bounded (pacResolverTimeout) and the caller memoizes
// results, so the lock stays cold under load.
type gojaPACEngine struct {
	mu sync.Mutex
	vm *goja.Runtime
	fn goja.Callable
}

// compilePAC compiles a PAC script, installs the host functions backed by
// res, and locates the FindProxyForURL (or FindProxyForURLEx) entry point.
func compilePAC(script string, res pacResolver) (Engine, error) {
	prog, err := goja.Compile("proxy.pac", script, false) // non-strict: corporate PACs are sloppy ES3/5
	if err != nil {
		return nil, fmt.Errorf("proxykit: compile PAC: %w", err)
	}
	vm := goja.New()
	if err := registerPACHelpers(vm, res); err != nil {
		return nil, fmt.Errorf("proxykit: register PAC helpers: %w", err)
	}
	if _, err := vm.RunProgram(prog); err != nil {
		return nil, fmt.Errorf("proxykit: load PAC: %w", err)
	}
	fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		if fn, ok = goja.AssertFunction(vm.Get("FindProxyForURLEx")); !ok {
			return nil, fmt.Errorf("proxykit: PAC defines no FindProxyForURL[Ex]: %w", errors.ErrUnsupported)
		}
	}
	return &gojaPACEngine{vm: vm, fn: fn}, nil
}

// FindProxy runs FindProxyForURL(rawURL, host). A watchdog interrupts the
// runtime if evaluation exceeds the deadline (the sooner of ctx and
// pacEvalTimeout), so a buggy PAC cannot hang the dial.
func (e *gojaPACEngine) FindProxy(ctx context.Context, rawURL, host string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	timeout := pacEvalTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	// Watchdog: interrupt a runaway PAC. We wait for the watchdog goroutine
	// to exit (watchdog channel) BEFORE ClearInterrupt, so a late Interrupt
	// can never leak into the next evaluation.
	//
	// vm.Interrupt only unwinds interpreted JS: a pathological native call —
	// a catastrophic RegExp through goja's regexp engine, say — can still run
	// past the deadline; DNS helpers are separately bounded by
	// pacResolverTimeout. PAC from Config.PAC/PACURL is operator-supplied
	// (trusted); the only attacker-influenceable path, DNS-WPAD, is a
	// deliberate opt-in (Config.WPAD).
	done := make(chan struct{})
	watchdog := make(chan struct{})
	go func() {
		defer close(watchdog)
		select {
		case <-done:
		case <-time.After(timeout):
			e.vm.Interrupt(errPACTimeout)
		}
	}()

	v, err := e.fn(goja.Undefined(), e.vm.ToValue(rawURL), e.vm.ToValue(host))

	close(done)
	<-watchdog
	e.vm.ClearInterrupt()

	if err != nil {
		return "", fmt.Errorf("proxykit: PAC eval: %w", err)
	}
	return v.String(), nil
}

// Close releases engine resources. Currently a no-op: the runtime holds no
// background goroutines (the watchdog is per-call), so there is nothing to
// release. Kept on the interface for forward compatibility.
func (e *gojaPACEngine) Close() {}
