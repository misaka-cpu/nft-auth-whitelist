// Package sshpush pushes a signed allow.json to a receiver over SSH by piping
// it to the remote's stdin. The remote's authorized_keys forced command runs
// nft-auth-receive, so this package NEVER specifies a remote command and never
// uses scp. It shells out to the system ssh binary via os/exec with an argument
// vector (no shell string), so untrusted config values cannot inject commands.
package sshpush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// maxCapture caps how much stdout/stderr we keep, so a chatty or hostile remote
// cannot blow up the audit log.
const maxCapture = 4 << 10 // 4 KiB

// Target is one SSH receiver.
type Target struct {
	Name                  string
	User                  string
	Host                  string
	Port                  int
	IdentityFile          string
	StrictHostKeyChecking bool
	KnownHostsFile        string
}

// Result is the outcome of a single push attempt.
type Result struct {
	Name       string
	Host       string
	Port       int
	DurationMs int64
	OK         bool
	ExitStatus int
	// Stdout is the truncated remote stdout (e.g. "ok entries=1 output=...").
	Stdout string
	// Reason is a short, non-secret failure description (timeout / truncated
	// stderr / exec error). Empty on success.
	Reason string
}

// Pusher runs ssh. SSHPath defaults to "ssh"; tests override it with a fake.
type Pusher struct {
	SSHPath string
}

// BuildArgs returns the ssh argument vector (excluding the ssh binary). It never
// includes a remote command: the receiver's forced command supplies that.
func BuildArgs(t Target, timeout time.Duration) []string {
	connectTimeout := int(timeout.Seconds())
	if connectTimeout < 1 {
		connectTimeout = 1
	}
	args := []string{
		"-i", t.IdentityFile,
		"-p", strconv.Itoa(t.Port),
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(connectTimeout),
	}
	if t.StrictHostKeyChecking {
		args = append(args, "-o", "StrictHostKeyChecking=yes")
	} else {
		args = append(args, "-o", "StrictHostKeyChecking=no")
	}
	if t.KnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+t.KnownHostsFile)
	}
	// Destination last; still no remote command.
	args = append(args, t.User+"@"+t.Host)
	return args
}

// Push pipes payload to the target over ssh, enforcing a hard timeout. It always
// returns a Result (never a Go error); failures are reported in Result.OK/Reason
// so the caller's auth flow is never broken by a push problem.
func (p Pusher) Push(ctx context.Context, t Target, payload []byte, timeout time.Duration) Result {
	sshPath := p.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	res := Result{Name: t.Name, Host: t.Host, Port: t.Port}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, sshPath, BuildArgs(t, timeout)...)
	cmd.Stdin = bytes.NewReader(payload)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	// After the context kills ssh, do not let a lingering child holding the
	// output pipe block Run() (and thus the auth handler) indefinitely.
	cmd.WaitDelay = 2 * time.Second

	start := time.Now()
	runErr := cmd.Run()
	res.DurationMs = time.Since(start).Milliseconds()
	res.Stdout = truncate(out.String())

	if cctx.Err() == context.DeadlineExceeded {
		res.OK = false
		res.Reason = fmt.Sprintf("timeout after %s", timeout)
		return res
	}
	if runErr != nil {
		res.OK = false
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitStatus = exitErr.ExitCode()
		} else {
			res.ExitStatus = -1
		}
		if s := truncate(errb.String()); s != "" {
			res.Reason = s
		} else {
			res.Reason = runErr.Error()
		}
		return res
	}

	res.OK = true
	res.ExitStatus = 0
	return res
}

// truncate trims to maxCapture bytes and collapses to a single trimmed line-ish
// summary suitable for an audit field.
func truncate(s string) string {
	if len(s) > maxCapture {
		s = s[:maxCapture] + "...(truncated)"
	}
	return trimSpaceASCII(s)
}

// trimSpaceASCII trims leading/trailing spaces and newlines without pulling in
// unicode tables; the captured text is short and ASCII in practice.
func trimSpaceASCII(s string) string {
	start := 0
	for start < len(s) && isSpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
