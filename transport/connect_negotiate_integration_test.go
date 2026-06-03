//go:build integration && !windows && !proxykit_nokerberos

package transport_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/durck/proxykit/auth"
	"github.com/durck/proxykit/transport"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	krb5Realm            = "PROXYKIT.TEST"
	krb5ClientPrincipal  = "alice@PROXYKIT.TEST"
	krb5ClientPassword   = "alice-password"
	krb5ServicePrincipal = "HTTP/proxy.proxykit.test"
)

func TestConnect_Negotiate_FullDance(t *testing.T) {
	env := setupKrb5Docker(t)

	kt, err := keytab.Load(env.proxyKeytab)
	if err != nil {
		t.Fatalf("load proxy keytab: %v", err)
	}
	acceptor := spnego.SPNEGOService(
		kt,
		service.KeytabPrincipal(krb5ServicePrincipal),
		service.DecodePAC(false),
	)

	backend := httpEcho(t)
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	var gotToken []byte
	var tokenAccepted bool

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		c1, err := ln.Accept()
		if err != nil {
			return
		}
		func() {
			defer c1.Close()
			br := bufio.NewReader(c1)
			req, err := http.ReadRequest(br)
			if err != nil {
				t.Errorf("initial ReadRequest: %v", err)
				return
			}
			if got := req.Header.Get("Proxy-Authorization"); got != "" {
				t.Errorf("initial Proxy-Authorization = %q, want empty", got)
				return
			}
			_, _ = io.WriteString(c1, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
				"Proxy-Authenticate: Negotiate\r\n\r\n")
		}()

		c2, err := ln.Accept()
		if err != nil {
			return
		}
		defer c2.Close()
		br := bufio.NewReader(c2)

		req, err := http.ReadRequest(br)
		if err != nil {
			t.Errorf("authenticated ReadRequest: %v", err)
			return
		}
		authz := req.Header.Get("Proxy-Authorization")
		if !strings.HasPrefix(authz, "Negotiate ") {
			t.Errorf("authenticated Proxy-Authorization = %q, want Negotiate prefix", authz)
			return
		}
		gotToken, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Negotiate "))
		if err != nil {
			t.Errorf("Negotiate token base64: %v", err)
			return
		}
		var token spnego.SPNEGOToken
		if err := token.Unmarshal(gotToken); err != nil {
			t.Errorf("SPNEGO token unmarshal: %v", err)
			return
		}
		ok, _, status := acceptor.AcceptSecContext(&token)
		if !ok || status.Code != gssapi.StatusComplete {
			t.Errorf("SPNEGO token validation ok=%v status=%v", ok, status)
			return
		}
		tokenAccepted = true

		_, _ = io.WriteString(c2, "HTTP/1.1 200 OK\r\n\r\n")
		target, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			t.Errorf("dial backend: %v", err)
			return
		}
		defer target.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(target, br); done <- struct{}{} }()
		go func() { io.Copy(c2, target); done <- struct{}{} }()
		<-done
	}()

	t.Setenv("KRB5_CONFIG", env.krb5Conf)
	t.Setenv("KRB5CCNAME", "FILE:"+env.clientCCache)

	c := &transport.Connect{
		ProxyURL: mustParseURL(t, "http://"+ln.Addr().String()),
		Auth:     []auth.Authenticator{auth.Negotiate(krb5ServicePrincipal)},
		Timeout:  10 * time.Second,
	}

	conn, err := c.DialContext(context.Background(), "tcp", backendAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("tunnel response %q does not contain hello", body)
	}

	<-serverDone

	if len(gotToken) == 0 {
		t.Fatal("Negotiate token was empty")
	}
	if !tokenAccepted {
		t.Fatal("mock proxy did not accept the SPNEGO token")
	}
}

type krb5DockerEnv struct {
	krb5Conf     string
	clientCCache string
	proxyKeytab  string
}

func setupKrb5Docker(t *testing.T) krb5DockerEnv {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv("CI") == "true" || os.Getenv("PROXYKIT_KRB5_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker is required for integration tests: %v", err)
		}
		t.Skipf("docker is not available: %v", err)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), ".."))
	dockerCtx := filepath.Join(repoRoot, "testdata", "krb5")
	workDir := t.TempDir()

	image := "proxykit-krb5-test:" + fmt.Sprint(time.Now().UnixNano())
	runDocker(t, nil, "build", "-t", image, dockerCtx)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", image).Run() })

	publishHost := os.Getenv("PROXYKIT_KRB5_DOCKER_PUBLISH_HOST")
	if publishHost == "" {
		publishHost = "127.0.0.1"
	}
	containerID := runDocker(t, nil,
		"run", "-d",
		"-p", publishHost+"::88/tcp",
		image,
	)
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := exec.Command("docker", "logs", containerID).CombinedOutput(); err == nil {
				t.Logf("krb5 container logs:\n%s", logs)
			}
		}
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	kdcAddr := waitDockerPort(t, containerID, "88/tcp")
	krb5Conf := filepath.Join(workDir, "krb5.conf")
	if err := os.WriteFile(krb5Conf, []byte(krb5ConfFor(kdcAddr)), 0600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}

	clientCCache := filepath.Join(workDir, "alice.ccache")
	waitDockerKinit(t, containerID)
	runDocker(t, nil, "cp", containerID+":/out/alice.ccache", clientCCache)

	proxyKeytab := filepath.Join(workDir, "proxy.keytab")
	runDocker(t, nil, "cp", containerID+":/out/proxy.keytab", proxyKeytab)
	if _, err := os.Stat(proxyKeytab); err != nil {
		t.Fatalf("proxy keytab was not produced: %v", err)
	}

	return krb5DockerEnv{
		krb5Conf:     krb5Conf,
		clientCCache: clientCCache,
		proxyKeytab:  proxyKeytab,
	}
}

func krb5ConfFor(kdcAddr string) string {
	return fmt.Sprintf(`[libdefaults]
 default_realm = %[1]s
 dns_lookup_realm = false
 dns_lookup_kdc = false
 udp_preference_limit = 1
 rdns = false
 noaddresses = true
 forwardable = true
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
 %[1]s = {
  kdc = %[2]s
 }

[domain_realm]
 .proxykit.test = %[1]s
 proxykit.test = %[1]s
`, krb5Realm, kdcAddr)
}

func waitDockerPort(t *testing.T, containerID, port string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", containerID, port).CombinedOutput()
		last = strings.TrimSpace(string(out))
		if err == nil && last != "" {
			if hostPort := normalizeDockerHostPort(last); hostPort != "" {
				return hostPort
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("docker port %s did not become available, last output: %s", port, last)
	return ""
}

func normalizeDockerHostPort(raw string) string {
	line := strings.TrimSpace(strings.Split(raw, "\n")[0])
	if line == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if override := os.Getenv("PROXYKIT_KRB5_KDC_HOST"); override != "" {
		host = override
	}
	return net.JoinHostPort(host, port)
}

func waitDockerKinit(t *testing.T, containerID string) {
	t.Helper()
	script := fmt.Sprintf("printf '%%s\\n' %q | KRB5_CONFIG=/etc/krb5.conf kinit -c /out/alice.ccache %s && chmod 0644 /out/alice.ccache", krb5ClientPassword, krb5ClientPrincipal)
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "exec", containerID, "sh", "-c", script).CombinedOutput()
		last = strings.TrimSpace(string(out))
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("kinit did not succeed, last output: %s", last)
}

func runDocker(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
