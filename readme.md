# caddy-certwarmup

A [Caddy](https://caddyserver.com/) listener wrapper that holds back accepting
connections until the certificates Caddy already has in storage are loaded.
It exists to make restarts with socket activation lossless.

## Why

With systemd socket activation (Caddy's `fd/N` and `fdgram/N` binds), the
listening sockets belong to systemd and stay open while Caddy restarts. Clients
connecting during the restart aren't refused, they queue up in the socket's
accept backlog, and the new process picks them up as soon as it starts.

The trouble is the order in which Caddy starts. It begins accepting on its
listeners first, and only then starts managing certificates, which loads the
existing ones from storage asynchronously. Caddy does this deliberately, so the
ACME solvers can't grab the HTTP and HTTPS ports before the servers do. Unless
on-demand TLS is enabled, a TLS handshake for a certificate that isn't in the
in-memory cache yet doesn't fall back to storage, it just fails:

```
remote error: tls: internal error
```

Without socket activation this window lasts a few milliseconds and is rarely
hit. With socket activation, every connection that queued up during the
restart is waiting in the backlog and is accepted inside exactly that window,
so restarts reliably fail a chunk of them, even though every certificate is
sitting on disk.

`cert_warmup` closes that window. On the first config load after the process
starts, the first `Accept` blocks until every name automatic HTTPS manages a
certificate for is in the cache. Loading from storage takes milliseconds, so
that is usually all it waits.

## What it doesn't do

It is only meant to cover certificates that already exist in storage:

- **Certificates that need to be issued** aren't waited on beyond `max_wait`
  (default `5s`). After that, connections are accepted and a warning lists the
  names still pending. Handshakes for those names fail until issuance finishes,
  just as they would without this module.
- **Config reloads** never wait. The process already has its certificates
  cached, and holding back accepts while new names get issued would stall every
  site.
- **On-demand TLS** names aren't waited on, they're obtained during the
  handshake anyway.
- **HTTP/3** isn't covered. QUIC doesn't use listener wrappers, and during a
  restart the old process keeps reading the shared UDP socket, so new QUIC
  connections in that window fail regardless. Clients fall back to TCP.

## Usage

Build Caddy with the module:

```sh
xcaddy build --with github.com/daaku/caddy-certwarmup
```

or import it in your own `main.go`:

```go
import _ "github.com/daaku/caddy-certwarmup"
```

Add it before `tls` in the servers' listener wrappers:

```Caddyfile
{
	servers {
		listener_wrappers {
			cert_warmup [<max_wait>]
			tls
		}
	}
}
```

The JSON equivalent:

```json
{
  "listener_wrappers": [
    { "wrapper": "cert_warmup", "max_wait": "5s" },
    { "wrapper": "tls" }
  ]
}
```

## Socket Activation Example

A `caddy.socket` holding HTTP, HTTPS and HTTP/3:

```ini
[Socket]
ListenStream=80
ListenStream=443
ListenDatagram=443
BindIPv6Only=both

[Install]
WantedBy=sockets.target
```

Bind to the sockets it passes in, in the order they are listed. Bound to the
sockets this way, Caddy can't start its own HTTP to HTTPS redirect server, so
add the redirect yourself:

```Caddyfile
{
	# without a limit, long lived connections hang every stop and restart
	grace_period 10s

	servers {
		protocols h1 h2
		listener_wrappers {
			cert_warmup
			tls
		}
	}
	default_bind fd/4
	default_bind fdgram/5 {
		protocols h3
	}
	auto_https disable_redirects
}

http:// {
	bind fd/3 {
		protocols h1
	}
	redir https://{host}{uri} 308
}
```

In `caddy.service`, use `Type=notify`, leave Caddy's default `SIGTERM` handling
alone (it is the graceful stop), and set `TimeoutStopSec` comfortably above
`grace_period`.
