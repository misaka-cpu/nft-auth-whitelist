// Package audit writes append-only JSON Lines audit records.
//
// Callers must never place secrets (password, pull_token, hmac_secret) into the
// detail map; this package only records what it is given.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Action constants shared by both binaries.
const (
	ActionAuthSuccess     = "auth.success"
	ActionAuthFail        = "auth.fail"
	ActionEntryAdd        = "entry.add"
	ActionEntryRefresh    = "entry.refresh"
	ActionEntryExpire     = "entry.expire"
	ActionPullSuccess     = "pull.success"
	ActionPullFail        = "pull.fail"
	ActionReceiveSuccess  = "receive.success"
	ActionReceiveFail     = "receive.fail"
	ActionPushStart       = "push.start"
	ActionPushSuccess     = "push.success"
	ActionPushFail        = "push.fail"
	ActionPushReconcile   = "push.reconcile"
	ActionSignatureOK     = "signature.ok"
	ActionSignatureFail   = "signature.fail"
	ActionOutputWriteOK   = "output.write.success"
	ActionOutputWriteFail = "output.write.fail"
	ActionNFTDryRun       = "nft.dry_run"
	ActionNFTApplySuccess = "nft.apply.success"
	ActionNFTApplyFail    = "nft.apply.fail"
	ActionRateLimited     = "auth.rate_limited"
	ActionAuthFrozen      = "auth.frozen"
)

// Result values.
const (
	ResultOK    = "ok"
	ResultWarn  = "warn"
	ResultError = "error"
)

// Logger is a concurrency-safe JSON Lines writer.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

type event struct {
	Timestamp string                 `json:"timestamp"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Detail    map[string]interface{} `json:"detail,omitempty"`
}

// New opens (creating if needed, append mode, 0600) the audit log at path. An
// empty path logs to stderr.
func New(path string) (*Logger, error) {
	if path == "" {
		return &Logger{w: os.Stderr}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{w: f, closer: f}, nil
}

// NewWithWriter is used in tests.
func NewWithWriter(w io.Writer) *Logger { return &Logger{w: w} }

// Log writes a single audit record. Errors writing the audit log are ignored to
// avoid taking down the service over a logging failure.
func (l *Logger) Log(action, result string, detail map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    action,
		Result:    result,
		Detail:    detail,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = l.w.Write(b)
}

// Close closes the underlying file if any.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}
