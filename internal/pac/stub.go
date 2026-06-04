//go:build !proxykit_pac

package pac

import (
	"errors"
	"fmt"
)

// This file is compiled into the DEFAULT build (no proxykit_pac tag). It
// wires NewEngine to a stub that reports the feature is unavailable, so
// the goja dependency is never pulled in. Build with -tags proxykit_pac
// to get the real evaluator (eval.go).
func init() {
	NewEngine = func(string) (Engine, error) {
		return nil, fmt.Errorf("proxykit: built without PAC support (proxykit_pac): %w", errors.ErrUnsupported)
	}
}
