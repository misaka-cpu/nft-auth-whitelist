package sshpush

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleTarget() Target {
	return Target{
		Name:                  "test-vps",
		User:                  "nftauth",
		Host:                  "203.0.113.10",
		Port:                  2222,
		IdentityFile:          "/root/.ssh/nft_auth_push_test",
		StrictHostKeyChecking: true,
		KnownHostsFile:        "/root/.ssh/known_hosts",
	}
}

func TestBuildArgsNoShellNoRemoteCommand(t *testing.T) {
	args := BuildArgs(sampleTarget(), 10*time.Second)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"-i /root/.ssh/nft_auth_push_test",
		"-p 2222",
		"BatchMode=yes",
		"ConnectTimeout=10",
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=/root/.ssh/known_hosts",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q; got %q", want, joined)
		}
	}

	// Destination must be the last arg and be user@host with NO remote command.
	if args[len(args)-1] != "nftauth@203.0.113.10" {
		t.Fatalf("last arg must be the destination, got %q", args[len(args)-1])
	}
}

func TestBuildArgsStrictDisabledAndNoKnownHosts(t *testing.T) {
	tg := sampleTarget()
	tg.StrictHostKeyChecking = false
	tg.KnownHostsFile = ""
	joined := strings.Join(BuildArgs(tg, 10*time.Second), " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Error("expected StrictHostKeyChecking=no")
	}
	if strings.Contains(joined, "UserKnownHostsFile") {
		t.Error("must not include UserKnownHostsFile when known_hosts_file empty")
	}
}

// writeFakeSSH writes an executable shell script standing in for ssh.
func writeFakeSSH(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-ssh.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPushSuccess(t *testing.T) {
	// Consume stdin and emit a receive-style success line.
	fake := writeFakeSSH(t, `cat >/dev/null; echo "ok entries=1 output=/var/lib/nft-auth-whitelist/allow.txt"; exit 0`)
	p := Pusher{SSHPath: fake}
	r := p.Push(context.Background(), sampleTarget(), []byte(`{"version":1}`), 5*time.Second)
	if !r.OK {
		t.Fatalf("expected success, got %+v", r)
	}
	if !strings.HasPrefix(r.Stdout, "ok entries=1") {
		t.Fatalf("stdout = %q", r.Stdout)
	}
	if r.ExitStatus != 0 {
		t.Fatalf("exit = %d", r.ExitStatus)
	}
}

func TestPushFailureNonZero(t *testing.T) {
	fake := writeFakeSSH(t, `cat >/dev/null; echo "boom" 1>&2; exit 7`)
	p := Pusher{SSHPath: fake}
	r := p.Push(context.Background(), sampleTarget(), []byte(`{}`), 5*time.Second)
	if r.OK {
		t.Fatal("expected failure")
	}
	if r.ExitStatus != 7 {
		t.Fatalf("exit = %d, want 7", r.ExitStatus)
	}
	if !strings.Contains(r.Reason, "boom") {
		t.Fatalf("reason should carry stderr summary, got %q", r.Reason)
	}
}

func TestPushTimeout(t *testing.T) {
	// exec replaces the shell so the context kill terminates sleep directly
	// (no lingering child holding the output pipe).
	fake := writeFakeSSH(t, `exec sleep 5`)
	p := Pusher{SSHPath: fake}
	start := time.Now()
	r := p.Push(context.Background(), sampleTarget(), []byte(`{}`), 300*time.Millisecond)
	if r.OK {
		t.Fatal("expected timeout failure")
	}
	if !strings.Contains(r.Reason, "timeout") {
		t.Fatalf("reason = %q, want timeout", r.Reason)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("push did not honour the timeout (hung)")
	}
}
