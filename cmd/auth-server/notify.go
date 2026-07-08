package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/audit"
	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

// notifier POSTs small JSON events to the optional webhook. Sends are
// fire-and-forget on a goroutine: a slow or dead webhook must never delay an
// auth response or a push. The webhook URL may embed a bot token, so it is
// never written to the audit log; failures are logged as notify.fail with the
// reason only.
type notifier struct {
	url    string
	client *http.Client
	audit  *audit.Logger
	wg     sync.WaitGroup
}

func newNotifier(cfg config.NotifyConfig, al *audit.Logger) *notifier {
	return &notifier{
		url:    cfg.WebhookURL,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		audit:  al,
	}
}

// Notify sends one event asynchronously. detail must not contain secrets.
func (n *notifier) Notify(event string, detail map[string]interface{}) {
	if n.url == "" {
		return
	}
	body, err := json.Marshal(map[string]interface{}{
		"event":  event,
		"time":   time.Now().UTC().Format(time.RFC3339),
		"detail": detail,
	})
	if err != nil {
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		resp, err := n.client.Post(n.url, "application/json", bytes.NewReader(body))
		if err != nil {
			// err may embed the URL (and thus a token): log only the event name.
			n.audit.Log(audit.ActionNotifyFail, audit.ResultWarn, map[string]interface{}{
				"event": event, "reason": "webhook request failed",
			})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			n.audit.Log(audit.ActionNotifyFail, audit.ResultWarn, map[string]interface{}{
				"event": event, "status": resp.StatusCode,
			})
		}
	}()
}

// wait blocks until all in-flight sends finish. Used by tests and shutdown.
func (n *notifier) wait() { n.wg.Wait() }
