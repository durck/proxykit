// Command basic dials a destination through an explicit proxy URL.
//
// Usage:
//
//	go run ./examples/basic --proxy http://proxy.corp:8080 example.com:443
//	go run ./examples/basic --proxy socks5://127.0.0.1:1080 example.com:443
//	go run ./examples/basic example.com:443                 # direct dial
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
	proxy := flag.String("proxy", "", "proxy URL (http://, https://, socks5://); empty means direct dial")
	timeout := flag.Duration("timeout", 10*time.Second, "per-attempt dial timeout")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: basic [--proxy URL] [--timeout 10s] HOST:PORT")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	target := flag.Arg(0)

	cfg := proxykit.Config{
		Manual:  *proxy,
		Timeout: *timeout,
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

	fmt.Printf("connected to %s — local %s, remote %s\n", target, conn.LocalAddr(), conn.RemoteAddr())
}
