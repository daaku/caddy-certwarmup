package certwarmup

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/daaku/ensure"
)

const subject = "warmup.test"

func TestUnmarshalCaddyfile(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected caddy.Duration
		err      string
	}{
		{name: "default", input: "cert_warmup"},
		{name: "max_wait", input: "cert_warmup 2s", expected: caddy.Duration(2 * time.Second)},
		{name: "invalid", input: "cert_warmup nope", err: "parsing max_wait"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var w CertWarmup
			err := w.UnmarshalCaddyfile(caddyfile.NewTestDispenser(c.input))
			if c.err != "" {
				ensure.Err(t, err, regexp.MustCompile(c.err))
				return
			}
			ensure.Nil(t, err)
			ensure.DeepEqual(t, w.MaxWait, c.expected)
		})
	}
}

// tempDir is like t.TempDir, but tolerates caddy's background certificate jobs
// still writing to it during cleanup.
func tempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "certwarmup")
	ensure.Nil(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	ensure.Nil(t, err)
	defer ln.Close()
	return ln.Addr().String()
}

// load starts caddy serving subject on addr, behind cert_warmup.
func load(t *testing.T, addr, storage string, maxWait time.Duration, issuer any) {
	loadPolicy(t, addr, storage, maxWait, map[string]any{"issuers": []any{issuer}})
}

func loadPolicy(t *testing.T, addr, storage string, maxWait time.Duration, policy map[string]any) {
	warmedUp.Store(false)
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"storage": map[string]any{"module": "file_system", "root": storage},
		"apps": map[string]any{
			"pki": map[string]any{"certificate_authorities": map[string]any{
				"local": map[string]any{"install_trust": false},
			}},
			"tls": map[string]any{"automation": map[string]any{"policies": []any{
				policy,
			}}},
			"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{
				"listen": []string{addr},
				"listener_wrappers": []any{
					map[string]any{"wrapper": "cert_warmup", "max_wait": maxWait},
					map[string]any{"wrapper": "tls"},
				},
				"automatic_https": map[string]any{"disable_redirects": true},
				"routes": []any{map[string]any{
					"match": []any{map[string]any{"host": []string{subject}}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"body":        "ok",
						"status_code": 200,
					}},
				}},
			}}},
		},
	}
	raw, err := json.Marshal(cfg)
	ensure.Nil(t, err)
	ensure.Nil(t, caddy.Load(raw, true))
}

func handshake(addr string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
		&tls.Config{ServerName: subject, InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	return conn.Close()
}

// A connection that is waiting when caddy starts, like those queued in a
// socket activated listener during a restart, must get a certificate.
func TestQueuedConnectionsGetCertificate(t *testing.T) {
	internal := map[string]any{"module": "internal"}
	storage := tempDir(t)
	addr := freeAddr(t)

	// the first run issues the certificate, the second loads it from storage,
	// which caddy does only after it starts accepting connections
	for run := range 2 {
		t.Run(fmt.Sprint(run), func(t *testing.T) {
			errs := make(chan error)
			for range 10 {
				go func() {
					// dial until caddy is listening, then hold the connection open
					for {
						conn, err := net.Dial("tcp", addr)
						if err != nil {
							time.Sleep(time.Millisecond)
							continue
						}
						tc := tls.Client(conn, &tls.Config{ServerName: subject, InsecureSkipVerify: true})
						errs <- tc.Handshake()
						tc.Close()
						return
					}
				}()
			}
			load(t, addr, storage, 5*time.Second, internal)
			defer caddy.Stop()
			for range 10 {
				ensure.Nil(t, <-errs)
			}
			ensure.True(t, warmedUp.Load())
		})
	}
}

// When a certificate can't be obtained, connections are accepted after max_wait.
func TestMaxWait(t *testing.T) {
	unreachable := map[string]any{"module": "acme", "ca": "https://127.0.0.1:1/directory"}
	addr := freeAddr(t)
	const maxWait = 300 * time.Millisecond
	start := time.Now()
	load(t, addr, tempDir(t), maxWait, unreachable)
	defer caddy.Stop()
	ensure.NotNil(t, handshake(addr))
	ensure.True(t, time.Since(start) >= maxWait)
	ensure.True(t, warmedUp.Load())
}

// Stopping must not wait on certificates that never arrive.
func TestStopWhileWaiting(t *testing.T) {
	unreachable := map[string]any{"module": "acme", "ca": "https://127.0.0.1:1/directory"}
	load(t, freeAddr(t), tempDir(t), time.Hour, unreachable)
	start := time.Now()
	ensure.Nil(t, caddy.Stop())
	ensure.True(t, time.Since(start) < 5*time.Second)
	ensure.False(t, warmedUp.Load())
}

// On-demand certificates aren't loaded until the handshake, so aren't waited on.
func TestSkipsOnDemand(t *testing.T) {
	addr := freeAddr(t)
	loadPolicy(t, addr, tempDir(t), time.Hour, map[string]any{
		"subjects":  []string{subject},
		"issuers":   []any{map[string]any{"module": "internal"}},
		"on_demand": true,
	})
	defer caddy.Stop()
	ensure.Nil(t, handshake(addr))
	ensure.True(t, warmedUp.Load())
}
