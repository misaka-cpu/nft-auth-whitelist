package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/clientip"
)

const (
	validPassword   = "test-password-0123456789"
	validToken      = "test-token-0123456789abcdef012345"
	validHMACSecret = "test-hmac-0123456789abcdef012345"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "puller.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Old configs without a "source" field must keep working and default to http.
func TestLoadPullerConfigDefaultsSourceHTTP(t *testing.T) {
	p := writeTempConfig(t, `{
	  "server_url": "https://auth.example.com/allow.json",
	  "pull_token": "example-test-token-0123456789abcdef",
	  "hmac_secret": "example-test-hmac-0123456789abcdef",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	c, err := LoadPullerConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Source != "http" {
		t.Fatalf("source = %q, want http", c.Source)
	}
}

// source=file parses with empty server_url/pull_token and ignores require_https.
func TestLoadPullerConfigFileSource(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "file",
	  "input_allow_json": "/var/lib/nft-auth-whitelist/inbox/allow.json",
	  "server_url": "",
	  "pull_token": "",
	  "hmac_secret": "example-test-hmac-0123456789abcdef",
	  "output_allow_txt": "/tmp/allow.txt",
	  "require_https": true
	}`)
	c, err := LoadPullerConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Source != "file" {
		t.Fatalf("source = %q, want file", c.Source)
	}
	if c.InputAllowJSON == "" {
		t.Fatal("input_allow_json should be set")
	}
}

func TestLoadPullerConfigFileSourceRequiresInput(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "file",
	  "input_allow_json": "",
	  "hmac_secret": "example-test-hmac-0123456789abcdef",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	_, err := LoadPullerConfig(p)
	if err == nil || !strings.Contains(err.Error(), "input_allow_json") {
		t.Fatalf("expected input_allow_json error, got %v", err)
	}
}

func TestLoadPullerConfigInvalidSource(t *testing.T) {
	p := writeTempConfig(t, `{
	  "source": "ftp",
	  "hmac_secret": "example-test-hmac-0123456789abcdef",
	  "output_allow_txt": "/tmp/allow.txt"
	}`)
	_, err := LoadPullerConfig(p)
	if err == nil || !strings.Contains(err.Error(), "source must be") {
		t.Fatalf("expected invalid source error, got %v", err)
	}
}

func fullReceiveJSON() string {
	return `{
	  "inbox_allow_json": "/var/lib/nft-auth-whitelist/inbox/allow.json",
	  "hmac_secret": "example-test-hmac-0123456789abcdef",
	  "output_allow_txt": "/var/lib/nft-auth-whitelist/allow.txt",
	  "output_state_json": "/var/lib/nft-auth-whitelist/pulled-state.json"
	}`
}

func TestLoadReceiveConfigDefaults(t *testing.T) {
	c, err := LoadReceiveConfig(writeTempConfig(t, fullReceiveJSON()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.InputMaxBytes != 1<<20 {
		t.Fatalf("input_max_bytes = %d, want %d", c.InputMaxBytes, 1<<20)
	}
	if c.Mode != "export" {
		t.Fatalf("mode = %q, want export", c.Mode)
	}
	if c.NFT.Enabled {
		t.Fatal("nft.enabled must default false")
	}
}

// serverJSON returns a minimal valid server config with the given push block
// spliced in (pass "" for no push block).
func serverJSON(push string) string {
	base := `{
	  "username": "admin",
	  "password": "example-test-password-0123456789",
	  "pull_token": "example-test-token-0123456789abcdef",
	  "hmac_secret": "example-test-hmac-0123456789abcdef"`
	if push != "" {
		base += ",\n  " + push
	}
	return base + "\n}"
}

func TestLoadServerConfigPushDefaultsDisabled(t *testing.T) {
	c, err := LoadServerConfig(writeTempConfig(t, serverJSON("")))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Push.Enabled {
		t.Fatal("push must default disabled")
	}
	if c.Push.TimeoutSeconds != 10 {
		t.Fatalf("timeout default = %d, want 10", c.Push.TimeoutSeconds)
	}
}

func TestLoadServerConfigPushTargetDefaults(t *testing.T) {
	push := `"push": {
	    "enabled": true,
	    "targets": [
	      {"name": "t1", "user": "nftauth", "host": "1.2.3.4", "identity_file": "/k", "known_hosts_file": "/known-hosts"}
	    ]
	  }`
	c, err := LoadServerConfig(writeTempConfig(t, serverJSON(push)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tg := c.Push.Targets[0]
	if tg.Port != 22 {
		t.Fatalf("port default = %d, want 22", tg.Port)
	}
	if !tg.StrictHostKey() {
		t.Fatal("strict_host_key_checking must default true")
	}
	if c.Push.TimeoutSeconds != 10 {
		t.Fatalf("timeout default = %d, want 10", c.Push.TimeoutSeconds)
	}
}

func TestLoadServerConfigPushStrictExplicitFalse(t *testing.T) {
	push := `"push": {
	    "enabled": true,
	    "targets": [
	      {"name": "t1", "user": "u", "host": "h", "identity_file": "/k", "strict_host_key_checking": false}
	    ]
	  }`
	c, err := LoadServerConfig(writeTempConfig(t, serverJSON(push)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Push.Targets[0].StrictHostKey() {
		t.Fatal("explicit strict_host_key_checking=false must be honoured")
	}
}

func TestLoadServerConfigPushEnabledEmptyTargets(t *testing.T) {
	push := `"push": {"enabled": true, "targets": []}`
	_, err := LoadServerConfig(writeTempConfig(t, serverJSON(push)))
	if err == nil || !strings.Contains(err.Error(), "targets is empty") {
		t.Fatalf("expected empty-targets error, got %v", err)
	}
}

func TestLoadServerConfigPushTargetMissingFields(t *testing.T) {
	for _, field := range []string{"name", "user", "host", "identity_file"} {
		full := map[string]string{"name": "t1", "user": "u", "host": "h", "identity_file": "/k", "known_hosts_file": "/known-hosts"}
		delete(full, field)
		parts := []string{}
		for k, v := range full {
			parts = append(parts, `"`+k+`": "`+v+`"`)
		}
		push := `"push": {"enabled": true, "targets": [{` + strings.Join(parts, ", ") + `}]}`
		_, err := LoadServerConfig(writeTempConfig(t, serverJSON(push)))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("missing %s: expected error naming the field, got %v", field, err)
		}
	}
}

func TestLoadReceiveConfigMissingFields(t *testing.T) {
	cases := map[string]string{
		"hmac_secret": `{
		  "inbox_allow_json": "/i",
		  "output_allow_txt": "/a",
		  "output_state_json": "/s"
		}`,
		"inbox_allow_json": `{
		  "hmac_secret": "example-test-hmac-0123456789abcdef",
		  "output_allow_txt": "/a",
		  "output_state_json": "/s"
		}`,
		"output_allow_txt": `{
		  "hmac_secret": "example-test-hmac-0123456789abcdef",
		  "inbox_allow_json": "/i",
		  "output_state_json": "/s"
		}`,
		"output_state_json": `{
		  "hmac_secret": "example-test-hmac-0123456789abcdef",
		  "inbox_allow_json": "/i",
		  "output_allow_txt": "/a"
		}`,
	}
	for field, body := range cases {
		_, err := LoadReceiveConfig(writeTempConfig(t, body))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("missing %s: expected error naming the field, got %v", field, err)
		}
	}
}

func TestEffectiveClientIPHeadersDefaultForNewTrustedProxyCIDRs(t *testing.T) {
	c := &ServerConfig{TrustedProxyCIDRs: []string{"127.0.0.1/32"}}
	got := c.EffectiveClientIPHeaders()
	want := []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}
	if len(got) != len(want) {
		t.Fatalf("headers = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("headers = %#v, want %#v", got, want)
		}
	}
}

func TestDefaultClientIPHeadersDelegatesToClientIPPackage(t *testing.T) {
	got := DefaultClientIPHeaders()
	want := clientip.DefaultHeaders()
	if len(got) != len(want) {
		t.Fatalf("headers = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("headers = %#v, want %#v", got, want)
		}
	}
	body, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `return []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}`) {
		t.Fatal("DefaultClientIPHeaders must delegate to clientip.DefaultHeaders instead of duplicating the list")
	}
}

func TestEffectiveClientIPHeadersPreservesLegacyRealIPHeader(t *testing.T) {
	c := &ServerConfig{
		TrustedProxies: []string{"10.0.0.1"},
		RealIPHeader:   "X-Forwarded-For",
	}
	got := c.EffectiveClientIPHeaders()
	if len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("headers = %#v, want legacy single header", got)
	}
}

func TestLegacyTrustedProxiesAloneDoNotEnableHeaders(t *testing.T) {
	c := &ServerConfig{TrustedProxies: []string{"10.0.0.1"}}
	if got := c.EffectiveClientIPHeaders(); len(got) != 0 {
		t.Fatalf("legacy trusted_proxies alone must not enable default headers, got %#v", got)
	}
}

func TestEffectiveTrustedProxyCIDRsIncludesLegacyEntries(t *testing.T) {
	c := &ServerConfig{
		TrustedProxyCIDRs: []string{"127.0.0.1/32"},
		TrustedProxies:    []string{"10.0.0.1"},
	}
	got := c.EffectiveTrustedProxyCIDRs()
	want := []string{"127.0.0.1/32", "10.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("trusted proxies = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trusted proxies = %#v, want %#v", got, want)
		}
	}
}

func validServerConfig() *ServerConfig {
	return &ServerConfig{
		Username:   "admin",
		Password:   validPassword,
		PullToken:  validToken,
		HMACSecret: validHMACSecret,
		AllowIPv4:  true,
	}
}

func validPullerConfig() *PullerConfig {
	return &PullerConfig{
		Source:         "http",
		ServerURL:      "https://auth.example.test/allow.json",
		PullToken:      validToken,
		HMACSecret:     validHMACSecret,
		OutputAllowTxt: "/tmp/allow.txt",
		AllowIPv4:      true,
		Mode:           "export",
		NFT:            NFTConfig{Table: "nft_auth_whitelist"},
	}
}

func TestServerConfigRejectsUnsafeSecrets(t *testing.T) {
	for name, mutate := range map[string]func(*ServerConfig){
		"placeholder username": func(c *ServerConfig) { c.Username = "change-me" },
		"placeholder password": func(c *ServerConfig) { c.Password = "change-me-password" },
		"short password":       func(c *ServerConfig) { c.Password = "short" },
		"short pull token":     func(c *ServerConfig) { c.PullToken = "short" },
		"short hmac secret":    func(c *ServerConfig) { c.HMACSecret = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			c := validServerConfig()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPullerAndReceiveRejectUnsafeSecrets(t *testing.T) {
	p := validPullerConfig()
	p.PullToken = "change-me-token"
	if err := p.Validate(); err == nil {
		t.Fatal("puller must reject placeholder pull_token")
	}

	r := &ReceiveConfig{
		InboxAllowJSON:  "/tmp/inbox.json",
		HMACSecret:      "short",
		OutputAllowTxt:  "/tmp/allow.txt",
		OutputStateJSON: "/tmp/state.json",
		AllowIPv4:       true,
		Mode:            "export",
		NFT:             NFTConfig{Table: "nft_auth_whitelist"},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("receiver must reject short hmac_secret")
	}
}

func TestServerConfigRejectsUnsafeTrustedProxyCIDRs(t *testing.T) {
	for _, cidr := range []string{"not-a-cidr", "0.0.0.0/0", "::/0"} {
		c := validServerConfig()
		c.TrustedProxyCIDRs = []string{cidr}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "trusted proxy") {
			t.Fatalf("%q: got %v", cidr, err)
		}
	}
}

func TestPushTargetRequiresValidPortAndKnownHosts(t *testing.T) {
	c := validServerConfig()
	c.Push = PushConfig{Enabled: true, Targets: []PushTarget{{
		Name: "po0", User: "nftauth", Host: "example.test",
		Port: 70000, IdentityFile: "/key",
	}}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("invalid port: got %v", err)
	}

	c.Push.Targets[0].Port = 22
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "known_hosts_file") {
		t.Fatalf("missing known_hosts_file: got %v", err)
	}
}

func TestNFTConfigRejectsOtherTablesAndInvalidPorts(t *testing.T) {
	for _, nft := range []NFTConfig{
		{Table: "filter"},
		{Table: "nft_auth_whitelist", ProtectedTCPPorts: []int{0}},
		{Table: "nft_auth_whitelist", ProtectedUDPPorts: []int{65536}},
	} {
		c := validPullerConfig()
		c.NFT = nft
		if err := c.Validate(); err == nil {
			t.Fatalf("expected validation error for %+v", nft)
		}
	}
}

func validReceiveConfig() *ReceiveConfig {
	return &ReceiveConfig{
		InputMaxBytes:   1 << 20,
		InboxAllowJSON:  "/var/lib/nft-auth-whitelist/inbox/allow.json",
		HMACSecret:      validHMACSecret,
		OutputAllowTxt:  "/var/lib/nft-auth-whitelist/allow.txt",
		OutputStateJSON: "/var/lib/nft-auth-whitelist/pulled-state.json",
		MaxEntries:      10,
		AllowIPv4:       true,
		Mode:            "export",
		NFT:             NFTConfig{Table: "nft_auth_whitelist"},
	}
}

func TestReceiveConfigRejectsCollidingPaths(t *testing.T) {
	if err := validReceiveConfig().Validate(); err != nil {
		t.Fatalf("valid receive config should pass, got %v", err)
	}
	for name, mutate := range map[string]func(*ReceiveConfig){
		"inbox == allow.txt": func(c *ReceiveConfig) { c.InboxAllowJSON = c.OutputAllowTxt },
		"state == allow.txt": func(c *ReceiveConfig) { c.OutputStateJSON = c.OutputAllowTxt },
		"inbox == state":     func(c *ReceiveConfig) { c.InboxAllowJSON = c.OutputStateJSON },
		"equal after clean":  func(c *ReceiveConfig) { c.InboxAllowJSON = "/var/lib/nft-auth-whitelist/./allow.txt" },
	} {
		t.Run(name, func(t *testing.T) {
			c := validReceiveConfig()
			mutate(c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
				t.Fatalf("expected distinct-paths error, got %v", err)
			}
		})
	}
}

func TestPullerConfigRejectsStateEqualsAllowTxt(t *testing.T) {
	c := validPullerConfig()
	c.OutputStateJSON = c.OutputAllowTxt
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "output_state_json must not equal output_allow_txt") {
		t.Fatalf("expected state==allow.txt error, got %v", err)
	}

	// An empty output_state_json is optional and must not be treated as a collision.
	c2 := validPullerConfig()
	c2.OutputStateJSON = ""
	if err := c2.Validate(); err != nil {
		t.Fatalf("empty output_state_json should be allowed, got %v", err)
	}
}

func TestPullerFileSourceRejectsInputCollisions(t *testing.T) {
	newCfg := func() *PullerConfig {
		c := validPullerConfig()
		c.Source = "file"
		c.ServerURL = ""
		c.PullToken = ""
		c.InputAllowJSON = "/var/lib/nft-auth-whitelist/inbox/allow.json"
		c.OutputAllowTxt = "/var/lib/nft-auth-whitelist/allow.txt"
		c.OutputStateJSON = "/var/lib/nft-auth-whitelist/state.json"
		return c
	}
	if err := newCfg().Validate(); err != nil {
		t.Fatalf("valid file-source config should pass, got %v", err)
	}

	c1 := newCfg()
	c1.InputAllowJSON = c1.OutputAllowTxt
	if err := c1.Validate(); err == nil || !strings.Contains(err.Error(), "input_allow_json must not equal") {
		t.Fatalf("input == allow.txt: got %v", err)
	}

	c2 := newCfg()
	c2.InputAllowJSON = c2.OutputStateJSON
	if err := c2.Validate(); err == nil || !strings.Contains(err.Error(), "input_allow_json must not equal") {
		t.Fatalf("input == state: got %v", err)
	}
}
