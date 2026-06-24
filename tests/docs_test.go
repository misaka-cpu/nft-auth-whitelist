// Package tests holds repo-level documentation checks: the README / SECURITY
// docs must keep the project's key safety promises explicit.
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestReadmeHTTPSBasicAuthWarning(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	// Must warn against Basic Auth over plain HTTP and recommend a reverse proxy.
	if !strings.Contains(readme, "Basic Auth") {
		t.Error("README must mention Basic Auth")
	}
	if !strings.Contains(readme, "纯 HTTP") {
		t.Error("README must warn about plain HTTP")
	}
	if !strings.Contains(readme, "Caddy") || !strings.Contains(readme, "Nginx") {
		t.Error("README must recommend Caddy/Nginx for HTTPS")
	}
}

func TestReadmeSidecarNoMainProjectChange(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "sidecar") {
		t.Error("README must describe the project as a sidecar")
	}
	if !strings.Contains(readme, "不修改主项目") {
		t.Error("README must state it does not modify the main project")
	}
	if !strings.Contains(readme, "nftables-nat-rust-enhanced") {
		t.Error("README must reference the main project name")
	}
}

func TestReadmePo0ActivePull(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "主动拉取") {
		t.Error("README must explain po0 actively pulls")
	}
	if !strings.Contains(readme, "不暴露") {
		t.Error("README must state po0 exposes no write API")
	}
}

func TestReadmeDefaultsNoNFTNoPermanent(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	for _, want := range []string{
		"默认不执行",   // default does not execute nft
		"export",  // export mode default
		"永久加白",    // no permanent whitelisting
		"提交任意 IP", // no arbitrary IP submission
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README must contain %q", want)
		}
	}
}

func TestReadmeExcludesForbiddenIntegrations(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	// These appear only in the "明确不做" (explicitly not doing) section.
	for _, want := range []string{"metowolf", "省墙", "Telegram", "WebUI", "多租户", "数据库"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README must explicitly disclaim %q", want)
		}
	}
}

func TestSecurityDocExists(t *testing.T) {
	sec := readRepoFile(t, "SECURITY.md")
	if !strings.Contains(sec, "HTTPS") || !strings.Contains(sec, "TTL") {
		t.Error("SECURITY.md must cover HTTPS and TTL")
	}
}

func TestReadmeDescribesThreeBinaries(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	for _, want := range []string{"nft-auth-server", "nft-auth-puller", "nft-auth-receive"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README must mention %s", want)
		}
	}
	if strings.Contains(readme, "\u5305\u542b\u4e24\u4e2a\u4e8c\u8fdb\u5236") {
		t.Error("README must not claim the project contains only two binaries")
	}
	if !strings.Contains(readme, "receive shadow") && !strings.Contains(readme, "shadow mode") {
		t.Error("README must describe the receive shadow deployment path")
	}
}

func TestDeployChecklistCoversDeliveryModes(t *testing.T) {
	checklist := readRepoFile(t, "docs/deploy-checklist.md")
	for _, want := range []string{
		"First-time validation",
		"Conditional revalidation",
		"Routine release checks",
		"RFC JP auth-server browser login",
		"nft-auth-receive",
		"Do not run nft",
	} {
		if !strings.Contains(checklist, want) {
			t.Errorf("deploy checklist must contain %q", want)
		}
	}
}
