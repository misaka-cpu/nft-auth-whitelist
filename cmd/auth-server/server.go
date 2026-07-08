package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/auth"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/clientip"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/ipx"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/signer"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/sshpush"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/store"
)

// envelopeTTL is how long an exported allow.json is advertised as fresh.
const envelopeTTL = 5 * time.Minute

// server wires the config, store, audit log and helpers into an http.Handler.
type server struct {
	cfg     *config.ServerConfig
	store   *store.Store
	audit   *audit.Logger
	client  *clientip.Extractor
	now     func() time.Time
	limiter *failureLimiter
	pusher  sshpush.Pusher
}

func newServer(cfg *config.ServerConfig, st *store.Store, al *audit.Logger) *server {
	return &server{
		cfg:   cfg,
		store: st,
		audit: al,
		client: clientip.New(clientip.Config{
			TrustedProxyCIDRs: cfg.EffectiveTrustedProxyCIDRs(),
			Headers:           cfg.EffectiveClientIPHeaders(),
		}),
		now:     time.Now,
		limiter: newFailureLimiter(cfg.RateLimit),
		pusher:  sshpush.Pusher{}, // SSHPath defaults to "ssh"
	}
}

// Handler returns the configured mux.
func (s *server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/allow.json", s.handleAllowJSON)
	mux.HandleFunc("/allow.txt", s.handleAllowTxt)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

// frozen reports whether the operator's freeze file exists. Any stat error
// other than existence counts as not frozen: the brake must never be able to
// take the service down on its own.
func (s *server) frozen() bool {
	if s.cfg.FreezeFile == "" {
		return false
	}
	_, err := os.Stat(s.cfg.FreezeFile)
	return err == nil
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ipString(ip net.IP, fallback string) string {
	if ip == nil {
		return fallback
	}
	return ip.String()
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resolved := s.client.Extract(r)
	peer := ipString(resolved.RemoteIP, clientHost(r))
	rateKey := ipString(resolved.ClientIP, peer)

	if !auth.CheckBasicAuth(r, s.cfg.Username, s.cfg.Password) {
		// Rate-limit repeated failures from the resolved client address.
		if s.limiter.blocked(rateKey, s.now()) {
			s.audit.Log(audit.ActionRateLimited, audit.ResultWarn, map[string]interface{}{
				"peer":      peer,
				"remote_ip": peer,
				"path":      r.URL.Path,
				"status":    http.StatusTooManyRequests,
			})
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		// NOTE: never log the submitted password.
		s.audit.Log(audit.ActionAuthFail, audit.ResultWarn, map[string]interface{}{
			"peer":      peer,
			"remote_ip": peer,
			"path":      r.URL.Path,
			"status":    http.StatusUnauthorized,
		})
		w.Header().Set("WWW-Authenticate", `Basic realm="nft-auth-whitelist"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Emergency freeze: while the freeze file exists, nothing is recorded and
	// even authenticated users only see 503. Checked after auth so the freeze
	// state is not observable without credentials.
	if s.frozen() {
		s.audit.Log(audit.ActionAuthFrozen, audit.ResultWarn, map[string]interface{}{
			"peer":      peer,
			"remote_ip": peer,
			"path":      r.URL.Path,
			"status":    http.StatusServiceUnavailable,
		})
		http.Error(w, "authentication is temporarily frozen by the operator", http.StatusServiceUnavailable)
		return
	}

	// Authenticated. The recorded IP is ALWAYS the request source IP; any
	// client-supplied IP value is ignored by design.
	ip := resolved.ClientIP
	if ip == nil {
		s.audit.Log(audit.ActionAuthFail, audit.ResultWarn, map[string]interface{}{
			"peer":      peer,
			"remote_ip": peer,
			"path":      r.URL.Path,
			"status":    http.StatusBadRequest,
			"reason":    "could not determine source IP",
		})
		http.Error(w, "could not determine source IP", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		s.renderAuthForm(w, r, ip)
		return
	}

	// Opportunistic purge of expired entries after authentication. The
	// background ticker also purges periodically; unauthenticated requests and
	// read-only GET requests must not be able to force a store scan/write.
	for _, cidr := range s.store.Purge(s.now()) {
		s.audit.Log(audit.ActionEntryExpire, audit.ResultOK, map[string]interface{}{"cidr": cidr})
	}

	// Optional /24 widening is only honoured when enabled in config AND
	// requested by the user via the auth form or ?scope=24, and only for IPv4.
	expand24 := false
	if s.cfg.AllowCIDRExpandIPv4 && requestedScope(r) == "24" {
		expand24 = true
	}

	cidr, err := ipx.CIDRForRequest(ip, expand24, s.cfg.AllowCIDRExpandIPv4, s.cfg.AllowIPv4, s.cfg.AllowIPv6)
	if err != nil {
		s.audit.Log(audit.ActionAuthFail, audit.ResultWarn, map[string]interface{}{
			"peer":             peer,
			"client_ip":        ip.String(),
			"client_ip_source": resolved.Source,
			"remote_ip":        peer,
			"path":             r.URL.Path,
			"status":           http.StatusForbidden,
			"reason":           err.Error(),
		})
		http.Error(w, "your address family is not allowed by this server", http.StatusForbidden)
		return
	}

	ttl := time.Duration(s.cfg.TTLSeconds) * time.Second
	res, err := s.store.Record(cidr, ip.String(), "web_auth", s.now(), ttl)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.Log(audit.ActionAuthSuccess, audit.ResultOK, map[string]interface{}{
		"ip":               ip.String(),
		"client_ip":        ip.String(),
		"client_ip_source": resolved.Source,
		"remote_ip":        peer,
		"path":             r.URL.Path,
		"status":           http.StatusOK,
	})
	action := audit.ActionEntryRefresh
	if res.IsNew {
		action = audit.ActionEntryAdd
	}
	s.audit.Log(action, audit.ResultOK, map[string]interface{}{
		"cidr":       res.Entry.CIDR,
		"expires_at": res.Entry.ExpiresAt.Format(time.RFC3339),
		"hit_count":  res.Entry.HitCount,
	})
	for _, c := range res.Evicted {
		s.audit.Log(audit.ActionEntryExpire, audit.ResultOK, map[string]interface{}{"cidr": c, "reason": "evicted"})
	}

	// Optional automatic SSH push of a freshly signed allow.json. A push failure
	// never affects the recorded entry above and never fails this request.
	var pushResults []sshpush.Result
	if s.cfg.Push.Enabled {
		pushResults = s.doPush(s.now())
	}

	s.renderRoot(w, res.Entry, pushResults)
}

func requestedScope(r *http.Request) string {
	if scope := r.URL.Query().Get("scope"); scope != "" {
		return scope
	}
	if r.Method != http.MethodPost {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.PostForm.Get("scope")
}

func (s *server) renderAuthForm(w http.ResponseWriter, r *http.Request, ip net.IP) {
	scope := "/32"
	if ip.To4() == nil {
		scope = "/128"
	} else if s.cfg.AllowCIDRExpandIPv4 && requestedScope(r) == "24" {
		scope = "/24"
	}

	action := "/"
	warn := ""
	if scope == "/24" {
		action = "/?scope=24"
		warn = `<p class="warn">⚠ 风险提示：/24 会放行整个 256 个地址的网段，请仅在你确实拥有该网段时使用。</p>`
	}

	ttl := time.Duration(s.cfg.TTLSeconds) * time.Second
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nft-auth-whitelist</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.6}
code{background:#f0f0f0;padding:.1rem .3rem;border-radius:.2rem}
.warn{color:#a00}
</style></head><body>
<h1>认证入口</h1>
<p>点击下面按钮后，服务端会把“你访问本页面的来源公网 IP”加入临时白名单。</p>
<table>
<tr><td>当前来源 IP</td><td><code>%s</code></td></tr>
<tr><td>将记录范围</td><td>%s</td></tr>
<tr><td>TTL</td><td>%s</td></tr>
</table>
%s
<form method="post" action="%s">
<p><button type="submit">认证当前 IP</button></p>
</form>
<p>说明：打开本页面只会显示确认页，不会写入白名单；提交按钮后才会记录或刷新过期时间。</p>
</body></html>
`,
		html.EscapeString(ip.String()),
		scope,
		ttl.String(),
		warn,
		html.EscapeString(action),
	)
}

func (s *server) renderRoot(w http.ResponseWriter, e signer.Entry, pushResults []sshpush.Result) {
	scope := "/32"
	if family := ipx.FamilyOfCIDR(e.CIDR); family == "ipv6" {
		scope = "/128"
	} else if len(e.CIDR) >= 3 && e.CIDR[len(e.CIDR)-3:] == "/24" {
		scope = "/24"
	}

	ttl := time.Duration(s.cfg.TTLSeconds) * time.Second
	warn := ""
	if scope == "/24" {
		warn = `<p class="warn">⚠ 风险提示：/24 会放行整个 256 个地址的网段，请仅在你确实拥有该网段时使用。</p>`
	}

	pushHTML := s.renderPushSection(pushResults)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nft-auth-whitelist</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.6}
code{background:#f0f0f0;padding:.1rem .3rem;border-radius:.2rem}
.warn{color:#a00}
table{border-collapse:collapse}td{padding:.2rem .8rem;border-bottom:1px solid #eee}
</style></head><body>
<h1>认证成功</h1>
<p>你的来源地址已被记录到临时白名单。该记录会在 TTL 到期后自动删除，不会永久加白。</p>
<table>
<tr><td>记录 IP</td><td><code>%s</code></td></tr>
<tr><td>记录 CIDR</td><td><code>%s</code></td></tr>
<tr><td>范围</td><td>%s</td></tr>
<tr><td>过期时间</td><td><code>%s</code></td></tr>
<tr><td>TTL</td><td>%s</td></tr>
<tr><td>命中次数</td><td>%d</td></tr>
</table>
%s
%s
<p>说明：本服务只记录“你访问本页面的来源公网 IP”，不接受任何由你自行提交的 IP。再次点击认证按钮可刷新过期时间。</p>
</body></html>
`,
		html.EscapeString(e.IP),
		html.EscapeString(e.CIDR),
		scope,
		e.ExpiresAt.Format(time.RFC3339),
		ttl.String(),
		e.HitCount,
		warn,
		pushHTML,
	)
}

// renderPushSection renders the per-target push results. It shows only the
// target name and a short non-secret status (never identity_file or any secret).
func (s *server) renderPushSection(results []sshpush.Result) string {
	if !s.cfg.Push.Enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<h2>Push results</h2>`)
	if len(results) == 0 {
		b.WriteString(`<p>Push: 无目标</p>`)
		return b.String()
	}
	b.WriteString(`<ul>`)
	for _, r := range results {
		status := "failed"
		detail := r.Reason
		if r.OK {
			status = "ok"
			detail = r.Stdout
		}
		// detail is already redacted of secrets by doPush; escape for HTML.
		line := fmt.Sprintf("<li>%s: %s, %dms", html.EscapeString(r.Name), status, r.DurationMs)
		if detail != "" {
			line += " — <code>" + html.EscapeString(detail) + "</code>"
		}
		line += "</li>"
		b.WriteString(line)
	}
	b.WriteString(`</ul>`)
	return b.String()
}
