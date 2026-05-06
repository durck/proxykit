// Command http_client demonstrates plugging proxykit into the stdlib
// http.Client as a custom transport.
//
// Usage:
//
//	go run ./examples/http_client --proxy http://proxy:8080 https://example.com
//	go run ./examples/http_client --auto https://example.com   # auto-detect
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/durck/proxykit"
)

func main() {
	proxy := flag.String("proxy", "", "explicit proxy URL; empty disables manual override")
	autoDetect := flag.Bool("auto", false, "enable proxy auto-detection (env vars, WinINET on Windows)")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: http_client [--proxy URL] [--auto] [--timeout 30s] URL")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	targetURL := flag.Arg(0)

	cfg := proxykit.Config{
		Manual:     *proxy,
		AutoDetect: *autoDetect,
		Timeout:    *timeout,
		OnLog: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	}

	client := &http.Client{
		Transport: proxykit.NewHTTPTransport(cfg),
		Timeout:   *timeout,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		log.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP %s\n", resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Printf("%s: %s\n", k, v)
		}
	}
	fmt.Println()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatalf("body: %v", err)
	}
}
