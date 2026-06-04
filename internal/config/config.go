// Package config defines and loads the JSON configuration for both binaries.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RateLimit controls login-failure throttling on the auth-server.
type RateLimit struct {
	Enabled              bool `json:"enabled"`
	MaxFailuresPerMinute int  `json:"max_failures_per_minute"`
}

// ServerConfig is the auth-server configuration.
type ServerConfig struct {
	Listen              string    `json:"listen"`
	BaseURL             string    `json:"base_url"`
	Username            string    `json:"username"`
	Password            string    `json:"password"`
	PullToken           string    `json:"pull_token"`
	HMACSecret          string    `json:"hmac_secret"`
	TTLSeconds          int       `json:"ttl_seconds"`
	MaxEntries          int       `json:"max_entries"`
	AllowIPv4           bool      `json:"allow_ipv4"`
	AllowIPv6           bool      `json:"allow_ipv6"`
	AllowCIDRExpandIPv4 bool      `json:"allow_cidr_expand_ipv4"`
	TrustedProxies      []string  `json:"trusted_proxies"`
	RealIPHeader        string    `json:"real_ip_header"`
	DataDir             string    `json:"data_dir"`
	AuditLog            string    `json:"audit_log"`
	RateLimit           RateLimit `json:"rate_limit"`
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
		TTLSeconds: 21600,
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
		c.TTLSeconds = 21600
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 200
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
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
	if !c.AllowIPv4 && !c.AllowIPv6 {
		return fmt.Errorf("at least one of allow_ipv4/allow_ipv6 must be true")
	}
	return nil
}

// LoadPullerConfig reads and validates the puller config, applying defaults.
func LoadPullerConfig(path string) (*PullerConfig, error) {
	c := &PullerConfig{
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

// Validate checks required fields for the puller.
func (c *PullerConfig) Validate() error {
	missing := []string{}
	if c.ServerURL == "" {
		missing = append(missing, "server_url")
	}
	if c.PullToken == "" {
		missing = append(missing, "pull_token")
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
	if c.Mode != "export" && c.Mode != "nft" {
		return fmt.Errorf("mode must be \"export\" or \"nft\", got %q", c.Mode)
	}
	if !c.AllowIPv4 && !c.AllowIPv6 {
		return fmt.Errorf("at least one of allow_ipv4/allow_ipv6 must be true")
	}
	return nil
}
