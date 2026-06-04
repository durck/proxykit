// Command autodetect dials through a system-detected proxy.
//
// proxykit consults every detector registered for the host platform: the
// standard *_PROXY environment variables everywhere (HTTP_PROXY, HTTPS_PROXY,
// NO_PROXY and their lower-case forms); the Windows WinINET (HKCU) and WinHTTP
// (HKLM + IE) registries; the Linux /etc/environment file and the GNOME and KDE
// desktop settings; and the macOS system configuration via scutil. Built with
// -tags proxykit_pac it also honours a system-configured PAC URL.
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
