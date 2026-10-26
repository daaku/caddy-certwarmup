// Package certwarmup provides a Caddy listener wrapper that holds back accepting
// connections until certificates have been loaded from storage.
package certwarmup

import (
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&CertWarmup{})
}

// warmedUp is process wide, so only the first config loaded after start waits.
// Later reloads must not hold back accepts while their new certs are obtained.
var warmedUp atomic.Bool

// CertWarmup is a listener wrapper that holds back accepting connections until
// the managed certificates for all sites are in the cache.
//
// Caddy starts serving before it loads certificates from storage, which it
// does asynchronously. With socket activation the connections that queued up
// during a restart are accepted in that window and fail their TLS handshake.
type CertWarmup struct {
	// Maximum time to wait. Defaults to 5s.
	MaxWait caddy.Duration `json:"max_wait,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
	once   sync.Once
}

// CaddyModule returns the Caddy module information.
func (*CertWarmup) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.cert_warmup",
		New: func() caddy.Module { return new(CertWarmup) },
	}
}

// Provision implements caddy.Provisioner.
func (w *CertWarmup) Provision(ctx caddy.Context) error {
	w.ctx = ctx
	w.logger = ctx.Logger()
	if w.MaxWait == 0 {
		w.MaxWait = caddy.Duration(5 * time.Second)
	}
	return nil
}

// WrapListener implements caddy.ListenerWrapper.
func (w *CertWarmup) WrapListener(ln net.Listener) net.Listener {
	return &warmupListener{Listener: ln, w: w, closed: make(chan struct{})}
}

// subjects returns the names automatic HTTPS manages certificates for, the
// same way it finds them: host matchers in each server's top level routes.
func (w *CertWarmup) subjects() []string {
	appAny, err := w.ctx.AppIfConfigured("http")
	if err != nil {
		return nil
	}
	var policies []*caddytls.AutomationPolicy
	if tlsApp, err := w.ctx.AppIfConfigured("tls"); err == nil {
		if a := tlsApp.(*caddytls.TLS).Automation; a != nil {
			policies = a.Policies
		}
	}
	var names []string
	for _, srv := range appAny.(*caddyhttp.App).Servers {
		if srv.AutoHTTPS != nil && (srv.AutoHTTPS.Disabled || srv.AutoHTTPS.DisableCerts) {
			continue
		}
		for _, route := range srv.Routes {
			for _, set := range route.MatcherSets {
				for _, m := range set {
					hm, ok := m.(*caddyhttp.MatchHost)
					if !ok {
						continue
					}
					for _, d := range *hm {
						if strings.Contains(d, "{") || !certmagic.SubjectQualifiesForCert(d) {
							continue
						}
						if srv.AutoHTTPS != nil &&
							(slices.Contains(srv.AutoHTTPS.Skip, d) || slices.Contains(srv.AutoHTTPS.SkipCerts, d)) {
							continue
						}
						// on-demand certificates are loaded during the handshake
						if onDemand(policies, d) {
							continue
						}
						names = append(names, d)
					}
				}
			}
		}
	}
	return names
}

// onDemand reports whether the policy caddytls picks for name is on-demand.
// Only the explicitly configured policies are checked, the defaults it falls
// back to never are.
func onDemand(policies []*caddytls.AutomationPolicy, name string) bool {
	for _, ap := range policies {
		subjects := ap.Subjects()
		if len(subjects) == 0 {
			return ap.OnDemand
		}
		for _, s := range subjects {
			if certmagic.MatchWildcard(name, s) {
				return ap.OnDemand
			}
		}
	}
	return false
}

// wait blocks until every subject has a cached certificate, MaxWait passes, or
// closed is closed.
func (w *CertWarmup) wait(closed <-chan struct{}) {
	if warmedUp.Load() {
		return
	}
	start := time.Now()
	deadline := time.NewTimer(time.Duration(w.MaxWait))
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	pending := w.subjects()
	for {
		// caddytls.AllMatchingCertificates only takes the cache lock, unlike
		// TLS.HasCertificateForSubject which races with TLS.Manage.
		pending = slices.DeleteFunc(pending, func(name string) bool {
			return len(caddytls.AllMatchingCertificates(name)) > 0
		})
		if len(pending) == 0 {
			if warmedUp.CompareAndSwap(false, true) {
				w.logger.Debug("certificates cached", zap.Duration("waited", time.Since(start)))
			}
			return
		}
		select {
		case <-closed:
			return
		case <-deadline.C:
			if warmedUp.CompareAndSwap(false, true) {
				w.logger.Warn("accepting connections without cached certificates",
					zap.Duration("waited", time.Since(start)),
					zap.Strings("pending", pending))
			}
			return
		case <-tick.C:
		}
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	cert_warmup [<max_wait>]
func (w *CertWarmup) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// if no argument, we're done
	if !d.NextArg() {
		return nil
	}

	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return d.Errf("parsing max_wait: %v", err)
	}
	w.MaxWait = caddy.Duration(dur)
	return nil
}

type warmupListener struct {
	net.Listener
	w         *CertWarmup
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *warmupListener) Accept() (net.Conn, error) {
	l.w.once.Do(func() { l.w.wait(l.closed) })
	return l.Listener.Accept()
}

func (l *warmupListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// Interface guards
var (
	_ caddy.Provisioner     = (*CertWarmup)(nil)
	_ caddy.ListenerWrapper = (*CertWarmup)(nil)
	_ caddyfile.Unmarshaler = (*CertWarmup)(nil)
)
