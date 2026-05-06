// Command autodetect dials through a system-detected proxy.
//
// On any platform proxykit reads the standard *_PROXY environment
// variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY and lower-case forms).
// On Windows it additionally consults the WinINET ProxyServer registry
// value under HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
// Settings.
//
// Usage:
//
//	HTTPS_PROXY=http://proxy:8080 go run ./examples/autodetect example.com:443
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/durck/proxykit"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "per-attempt dial timeout")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: autodetect [--timeout 10s] HOST:PORT")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	target := flag.Arg(0)

	cfg := proxykit.Config{
		AutoDetect: true,
		Timeout:    *timeout,
		OnLog: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	}
	d := proxykit.NewDialer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fmt.Printf("connected to %s — remote %s\n", target, conn.RemoteAddr())
}
