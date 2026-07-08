// Package config defines and loads the JSON configuration for both binaries.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/clientip"
)

// RateLimit controls login-failure throttling on the auth-server.
type RateLimit struct {
	Enabled              bool `json:"enabled"`
	MaxFailuresPerMinute int  `json:"max_failures_per_minute"`
}

// PushTarget describes one SSH receiver the auth-server pushes allow.json to.
// The receiver's authorized_keys forced command runs nft-auth-receive, so no
// remote command is ever specified here.
type PushTarget struct {
	Name         string `json:"name"`
	User         string `json:"user"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	IdentityFile string `json:"identity_file"`
	// StrictHostKeyChecking defaults to true (a nil/absent value is treated as
	// true). A test environment may set it explicitly to false, but a real po0
	// MUST keep it true. Use StrictHostKey() to read the effective value.
	StrictHostKeyChecking *bool  `json:"strict_host_key_checking"`
	KnownHostsFile        string `json:"known_hosts_file"`
}

// StrictHostKey returns the effective strict-host-key-checking setting, which
// defaults to true when unset.
func (t PushTarget) StrictHostKey() bool {
	return t.StrictHostKeyChecking == nil || *t.StrictHostKeyChecking
}

// PushConfig controls whether (and where) the auth-server pushes a freshly
// signed allow.json after each successful authentication.
type PushConfig struct {
	Enabled        bool         `json:"enabled"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	Targets        []PushTarget `json:"targets"`
	// ReconcileIntervalSeconds is how often the server pushes the current
	// allowlist to all targets regardless of auth/purge activity, so a receiver
	// that missed a push (network blip, receiver downtime) converges back.
	// Absent defaults to 1800; an explicit 0 disables reconcile pushes.
	ReconcileIntervalSeconds *int `json:"reconcile_interval_seconds"`
}

// ReconcileInterval returns the effective reconcile push interval: 30 minutes
// when unset, 0 (disabled) when explicitly set to 0.
func (p PushConfig) ReconcileInterval() time.Duration {
	if p.ReconcileIntervalSeconds == nil {
		return 30 * time.Minute
	}
	return time.Duration(*p.ReconcileIntervalSeconds) * time.Second
}

// ServerConfig is the auth-server configuration.
type ServerConfig struct {
	Listen              string     `json:"listen"`
	BaseURL             string     `json:"base_url"`
	Username            string     `json:"username"`
	Password            string     `json:"password"`
	PullToken           string     `json:"pull_token"`
	HMACSecret          string     `json:"hmac_secret"`
	TTLSeconds          int        `json:"ttl_seconds"`
	MaxEntries          int        `json:"max_entries"`
	AllowIPv4           bool       `json:"allow_ipv4"`
	AllowIPv6           bool       `json:"allow_ipv6"`
	AllowCIDRExpandIPv4 bool       `json:"allow_cidr_expand_ipv4"`
	TrustedProxyCIDRs   []string   `json:"trusted_proxy_cidrs"`
	ClientIPHeaders     []string   `json:"client_ip_headers"`
	TrustedProxies      []string   `json:"trusted_proxies"` // legacy: use trusted_proxy_cidrs
	RealIPHeader        string     `json:"real_ip_header"`  // legacy: use client_ip_headers
	DataDir             string     `json:"data_dir"`
	AuditLog            string     `json:"audit_log"`
	RateLimit           RateLimit  `json:"rate_limit"`
	Push                PushConfig `json:"push"`
}

// NFTConfig is the optional, default-off nft guard configuration.
type NFTConfig struct {
	Enabled           bool   `json:"enabled"`
	Table             string `json:"table"`
	ProtectedTCPPorts []int  `json:"protected_tcp_ports"`
	ProtectedUDPPorts []int  `json:"protected_udp_ports"`
}

// PullerConfig is the puller configuration.
type PullerConfig struct {
	// Source selects where the signed allow.json comes from: "http" (default,
	// active pull from server_url) or "file" (read a locally delivered file from
	// input_allow_json, e.g. one pushed in over SSH/scp). An empty value is
	// treated as "http" for backward compatibility with older configs.
	Source          string    `json:"source"`
	InputAllowJSON  string    `json:"input_allow_json"`
	ServerURL       string    `json:"server_url"`
	PullToken       string    `json:"pull_token"`
	HMACSecret      string    `json:"hmac_secret"`
	IntervalSeconds int       `json:"interval_seconds"`
	OutputAllowTxt  string    `json:"output_allow_txt"`
	OutputStateJSON string    `json:"output_state_json"`
	MaxEntries      int       `json:"max_entries"`
	AllowIPv4       bool      `json:"allow_ipv4"`
	AllowIPv6       bool      `json:"allow_ipv6"`
	RequireHTTPS    bool      `json:"require_https"`
	Mode            string    `json:"mode"`
	NFT             NFTConfig `json:"nft"`
	AuditLog        string    `json:"audit_log"`
}

// ReceiveConfig is the nft-auth-receive configuration. The receiver reads a
// signed allow.json from stdin (an SSH forced command), so it needs neither
// server_url / pull_token nor require_https; only the verification + export
// fields plus an input size cap.
type ReceiveConfig struct {
	InputMaxBytes   int64     `json:"input_max_bytes"`
	InboxAllowJSON  string    `json:"inbox_allow_json"`
	HMACSecret      string    `json:"hmac_secret"`
	OutputAllowTxt  string    `json:"output_allow_txt"`
	OutputStateJSON string    `json:"output_state_json"`
	MaxEntries      int       `json:"max_entries"`
	AllowIPv4       bool      `json:"allow_ipv4"`
	AllowIPv6       bool      `json:"allow_ipv6"`
	Mode            string    `json:"mode"`
	NFT             NFTConfig `json:"nft"`
	AuditLog        string    `json:"audit_log"`
}

func readJSONFile(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// LoadServerConfig reads and validates the auth-server config, applying defaults.
func LoadServerConfig(path string) (*ServerConfig, error) {
	// Pre-populate defaults; absent JSON fields keep these values. This is how
	// boolean defaults such as AllowIPv4=true are honoured.
	c := &ServerConfig{
		Listen:     "127.0.0.1:8088",
		TTLSeconds: 1209600, // 14 days
		MaxEntries: 200,
		AllowIPv4:  true,
		DataDir:    "/var/lib/nft-auth-whitelist",
		RateLimit:  RateLimit{Enabled: true, MaxFailuresPerMinute: 10},
	}
	if err := readJSONFile(path, c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8088"
	}
	if c.TTLSeconds <= 0 {
		c.TTLSeconds = 1209600 // 14 days
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 200
	}
	if c.Push.TimeoutSeconds <= 0 {
		c.Push.TimeoutSeconds = 10
	}
	for i := range c.Push.Targets {
		if c.Push.Targets[i].Port == 0 {
			c.Push.Targets[i].Port = 22
		}
		if c.Push.Targets[i].StrictHostKeyChecking == nil {
			v := true
			c.Push.Targets[i].StrictHostKeyChecking = &v
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// DefaultClientIPHeaders returns the built-in trusted proxy header priority.
func DefaultClientIPHeaders() []string {
	return clientip.DefaultHeaders()
}

// EffectiveTrustedProxyCIDRs returns new trusted proxy CIDRs plus legacy
// trusted_proxies entries. Header trust remains disabled when the result is
// empty.
func (c *ServerConfig) EffectiveTrustedProxyCIDRs() []string {
	out := append([]string(nil), c.TrustedProxyCIDRs...)
	out = append(out, c.TrustedProxies...)
	return out
}

// EffectiveClientIPHeaders returns the configured header priority. The new
// client_ip_headers field wins; real_ip_header preserves the previous
// single-header behavior; trusted_proxy_cidrs without an explicit header list
// uses the built-in Cloudflare/reverse-proxy defaults.
func (c *ServerConfig) EffectiveClientIPHeaders() []string {
	if len(c.ClientIPHeaders) > 0 {
		return append([]string(nil), c.ClientIPHeaders...)
	}
	if strings.TrimSpace(c.RealIPHeader) != "" {
		return []string{c.RealIPHeader}
	}
	if len(c.TrustedProxyCIDRs) > 0 {
		return DefaultClientIPHeaders()
	}
	return nil
}

const (
	minPasswordLength = 16
	minTokenLength    = 32
	minHMACLength     = 32
	nftTableName      = "nft_auth_whitelist"
)

func rejectPlaceholder(name, value string) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "change-me") {
		return fmt.Errorf("%s still uses a sample placeholder", name)
	}
	return nil
}

func validateCredential(name, value string, min int) error {
	if err := rejectPlaceholder(name, value); err != nil {
		return err
	}
	if len(strings.TrimSpace(value)) < min {
		return fmt.Errorf("%s must be at least %d characters", name, min)
	}
	return nil
}

func validateTrustedProxyCIDRs(values []string) error {
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return fmt.Errorf("invalid trusted proxy entry")
			}
			if ip.To4() != nil {
				value += "/32"
			} else {
				value += "/128"
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR")
		}
		ones, bits := network.Mask.Size()
		if bits > 0 && ones == 0 {
			return fmt.Errorf("trusted proxy CIDR must not cover an entire address family")
		}
	}
	return nil
}

func (n NFTConfig) validate() error {
	if n.Table != nftTableName {
		return fmt.Errorf("nft.table must be %q", nftTableName)
	}
	ports := append(append([]int(nil), n.ProtectedTCPPorts...), n.ProtectedUDPPorts...)
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("protected port %d is outside 1..65535", port)
		}
	}
	return nil
}

// Validate checks required secret fields are present.
func (c *ServerConfig) Validate() error {
	missing := []string{}
	if c.Username == "" {
		missing = append(missing, "username")
	}
	if c.Password == "" {
		missing = append(missing, "password")
	}
	if c.PullToken == "" {
		missing = append(missing, "pull_token")
	}
	if c.HMACSecret == "" {
		missing = append(missing, "hmac_secret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config fields: %s", strings.Join(missing, ", "))
	}
	if err := rejectPlaceholder("username", c.Username); err != nil {
		return err
	}
	if err := validateCredential("password", c.Password, minPasswordLength); err != nil {
		return err
	}
	if err := validateCredential("pull_token", c.PullToken, minTokenLength); err != nil {
		return err
	}
	if err := validateCredential("hmac_secret", c.HMACSecret, minHMACLength); err != nil {
		return err
	}
	if err := validateTrustedProxyCIDRs(c.EffectiveTrustedProxyCIDRs()); err != nil {
		return err
	}
	if !c.AllowIPv4 && !c.AllowIPv6 {
		return fmt.Errorf("at least one of allow_ipv4/allow_ipv6 must be true")
	}
	if err := c.Push.validate(); err != nil {
		return err
	}
	return nil
}

// validate checks the push block. It is a no-op unless push is enabled.
func (p PushConfig) validate() error {
	if !p.Enabled {
		return nil
	}
	if len(p.Targets) == 0 {
		return fmt.Errorf("push.enabled is true but push.targets is empty")
	}
	if p.ReconcileIntervalSeconds != nil && *p.ReconcileIntervalSeconds < 0 {
		return fmt.Errorf("push.reconcile_interval_seconds must not be negative")
	}
	for i, t := range p.Targets {
		missing := []string{}
		if t.Name == "" {
			missing = append(missing, "name")
		}
		if t.User == "" {
			missing = append(missing, "user")
		}
		if t.Host == "" {
			missing = append(missing, "host")
		}
		if t.IdentityFile == "" {
			missing = append(missing, "identity_file")
		}
		label := t.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i)
		}
		if len(missing) > 0 {
			return fmt.Errorf("push target %s missing required fields: %s", label, strings.Join(missing, ", "))
		}
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("push target %s port must be within 1..65535", label)
		}
		if t.StrictHostKey() && strings.TrimSpace(t.KnownHostsFile) == "" {
			return fmt.Errorf("push target %s missing required field: known_hosts_file", label)
		}
	}
	return nil
}

// LoadPullerConfig reads and validates the puller config, applying defaults.
func LoadPullerConfig(path string) (*PullerConfig, error) {
	c := &PullerConfig{
		Source:          "http", // default; empty "source" in JSON keeps this
		IntervalSeconds: 60,
		MaxEntries:      200,
		AllowIPv4:       true,
		RequireHTTPS:    true, // default-on; explicit "false" in JSON overrides this
		Mode:            "export",
	}
	c.NFT.Table = "nft_auth_whitelist"
	if err := readJSONFile(path, c); err != nil {
		return nil, err
	}
	if c.Source == "" {
		c.Source = "http"
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 60
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 200
	}
	if c.Mode == "" {
		c.Mode = "export"
	}
	if c.NFT.Table == "" {
		c.NFT.Table = "nft_auth_whitelist"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// samePath reports whether two configured file paths refer to the same file
// after lexical cleaning. Empty paths are treated as unset and never collide.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// Validate checks required fields for the puller. Required fields depend on the
// source: "http" needs server_url + pull_token, "file" needs input_allow_json.
// hmac_secret and output_allow_txt are always required so the file-source path
// still verifies signatures and writes the same outputs as the http path.
func (c *PullerConfig) Validate() error {
	missing := []string{}
	switch c.Source {
	case "", "http":
		if c.ServerURL == "" {
			missing = append(missing, "server_url")
		}
		if c.PullToken == "" {
			missing = append(missing, "pull_token")
		}
	case "file":
		if c.InputAllowJSON == "" {
			missing = append(missing, "input_allow_json")
		}
	default:
		return fmt.Errorf("source must be \"http\" or \"file\", got %q", c.Source)
	}
	if c.HMACSecret == "" {
		missing = append(missing, "hmac_secret")
	}
	if c.OutputAllowTxt == "" {
		missing = append(missing, "output_allow_txt")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config fields: %s", strings.Join(missing, ", "))
	}
	if c.Source == "" || c.Source == "http" {
		if err := validateCredential("pull_token", c.PullToken, minTokenLength); err != nil {
			return err
		}
	}
	if err := validateCredential("hmac_secret", c.HMACSecret, minHMACLength); err != nil {
		return err
	}
	if c.Mode != "export" && c.Mode != "nft" {
		return fmt.Errorf("mode must be \"export\" or \"nft\", got %q", c.Mode)
	}
	if !c.AllowIPv4 && !c.AllowIPv6 {
		return fmt.Errorf("at least one of allow_ipv4/allow_ipv6 must be true")
	}
	if err := c.NFT.validate(); err != nil {
		return err
	}
	// Keep the operative allow.txt distinct from the secondary records so a state
	// (or file-source input) write can never clobber it.
	if samePath(c.OutputStateJSON, c.OutputAllowTxt) {
		return fmt.Errorf("output_state_json must not equal output_allow_txt")
	}
	if c.Source == "file" &&
		(samePath(c.InputAllowJSON, c.OutputAllowTxt) || samePath(c.InputAllowJSON, c.OutputStateJSON)) {
		return fmt.Errorf("input_allow_json must not equal output_allow_txt or output_state_json")
	}
	return nil
}

// LoadReceiveConfig reads and validates the receiver config, applying defaults.
func LoadReceiveConfig(path string) (*ReceiveConfig, error) {
	c := &ReceiveConfig{
		InputMaxBytes: 1 << 20, // 1 MiB
		MaxEntries:    200,
		AllowIPv4:     true,
		Mode:          "export",
	}
	c.NFT.Table = "nft_auth_whitelist"
	if err := readJSONFile(path, c); err != nil {
		return nil, err
	}
	if c.InputMaxBytes <= 0 {
		c.InputMaxBytes = 1 << 20
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 200
	}
	if c.Mode == "" {
		c.Mode = "export"
	}
	if c.NFT.Table == "" {
		c.NFT.Table = "nft_auth_whitelist"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks required fields for the receiver.
func (c *ReceiveConfig) Validate() error {
	missing := []string{}
	if c.HMACSecret == "" {
		missing = append(missing, "hmac_secret")
	}
	if c.InboxAllowJSON == "" {
		missing = append(missing, "inbox_allow_json")
	}
	if c.OutputAllowTxt == "" {
		missing = append(missing, "output_allow_txt")
	}
	if c.OutputStateJSON == "" {
		missing = append(missing, "output_state_json")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config fields: %s", strings.Join(missing, ", "))
	}
	if err := validateCredential("hmac_secret", c.HMACSecret, minHMACLength); err != nil {
		return err
	}
	if c.Mode != "export" && c.Mode != "nft" {
		return fmt.Errorf("mode must be \"export\" or \"nft\", got %q", c.Mode)
	}
	if !c.AllowIPv4 && !c.AllowIPv6 {
		return fmt.Errorf("at least one of allow_ipv4/allow_ipv6 must be true")
	}
	if err := c.NFT.validate(); err != nil {
		return err
	}
	// The inbox copy, state json, and the operative allow.txt must be three
	// distinct files; otherwise the "allow.txt written last" safety is broken and
	// a debug write could clobber the operative allowlist.
	if samePath(c.InboxAllowJSON, c.OutputAllowTxt) ||
		samePath(c.OutputStateJSON, c.OutputAllowTxt) ||
		samePath(c.InboxAllowJSON, c.OutputStateJSON) {
		return fmt.Errorf("inbox_allow_json, output_allow_txt and output_state_json must be three distinct paths")
	}
	return nil
}
