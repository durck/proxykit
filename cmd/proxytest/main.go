// Command proxytest is a diagnostic CLI for proxykit.
//
// Subcommands:
//
//	proxytest detect                                 list every proxy
//	                                                 candidate the installed
//	                                                 detectors can find on
//	                                                 the current host
//
//	proxytest dial [flags] HOST:PORT                 open a TCP connection
//	                                                 to HOST:PORT through
//	                                                 the configured chain
//
// Examples:
//
//	proxytest detect
//	proxytest dial example.com:443                            # direct
//	proxytest dial --auto example.com:443                     # use detect.All
//	proxytest dial --proxy http://proxy:8080 example.com:443  # explicit
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/durck/proxykit"
	"github.com/durck/proxykit/detect"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "detect":
		os.Exit(cmdDetect(os.Args[2:]))
	case "dial":
		os.Exit(cmdDial(os.Args[2:]))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  proxytest detect")
	fmt.Fprintln(w, "  proxytest dial [--proxy URL] [--auto] [--timeout DUR] HOST:PORT")
}

func cmdDetect(args []string) int {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	candidates, err := detect.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "detect: %v\n", err)
		// Continue — partial results are still useful.
	}

	if len(candidates) == 0 {
		fmt.Println("no proxy candidates found")
		return 0
	}

	fmt.Printf("%-40s  %-10s  %s\n", "URL", "FROM", "USER")
	for _, c := range candidates {
		fmt.Printf("%-40s  %-10s  %s\n", c.URL, c.From, c.User)
	}
	return 0
}

func cmdDial(args []string) int {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	proxy := fs.String("proxy", "", "explicit proxy URL (overrides auto-detect)")
	auto := fs.Bool("auto", false, "enable proxy auto-detection")
	timeout := fs.Duration("timeout", 10*time.Second, "per-attempt dial timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: proxytest dial [--proxy URL] [--auto] [--timeout DUR] HOST:PORT")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	target := fs.Arg(0)

	cfg := proxykit.Config{
		Manual:     *proxy,
		AutoDetect: *auto,
		Timeout:    *timeout,
		OnLog: func(level, msg string) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", level, msg)
		},
	}
	d := proxykit.NewDialer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		return 1
	}
	defer conn.Close()

	fmt.Printf("OK: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())
	return 0
}
