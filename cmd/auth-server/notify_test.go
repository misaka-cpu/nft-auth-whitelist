package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/misaka-cpu/nft-auth-whitelist/internal/config"
)

// webhookRecorder is an httptest server that records the JSON bodies it gets.
type webhookRecorder struct {
	ts *httptest.Server

	mu     sync.Mutex
	bodies []string
}

func newWebhookRecorder(t *testing.T) *webhookRecorder {
	t.Helper()
	w := &webhookRecorder{}
	w.ts = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.bodies = append(w.bodies, string(b))
		w.mu.Unlock()
	}))
	t.Cleanup(w.ts.Close)
	return w
}

func (w *webhookRecorder) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.bodies...)
}

func notifyServer(t *testing.T, hook *webhookRecorder, mutate func(*config.ServerConfig)) *server {
	t.Helper()
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.Notify = config.NotifyConfig{WebhookURL: hook.ts.URL, TimeoutSeconds: 5}
		if mutate != nil {
			mutate(c)
		}
	})
	return srv
}

func TestNotifyNewEntrySendsWebhook(t *testing.T) {
	hook := newWebhookRecorder(t)
	srv := notifyServer(t, hook, nil)

	if rec := authSuccess(t, srv); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	srv.notify.wait()

	got := hook.all()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 webhook call, got %d", len(got))
	}
	var ev struct {
		Event  string                 `json:"event"`
		Detail map[string]interface{} `json:"detail"`
	}
	if err := json.Unmarshal([]byte(got[0]), &ev); err != nil {
		t.Fatalf("webhook body is not JSON: %v", err)
	}
	if ev.Event != "entry.new" {
		t.Fatalf("event = %q, want entry.new", ev.Event)
	}
	if ev.Detail["cidr"] != "1.2.3.4/32" {
		t.Fatalf("detail.cidr = %v, want 1.2.3.4/32", ev.Detail["cidr"])
	}
}

func TestNotifyRefreshDoesNotSend(t *testing.T) {
	hook := newWebhookRecorder(t)
	srv := notifyServer(t, hook, nil)

	authSuccess(t, srv) // new -> 1 webhook
	authSuccess(t, srv) // refresh of the same IP -> no extra webhook
	srv.notify.wait()

	if got := hook.all(); len(got) != 1 {
		t.Fatalf("refresh must not notify; want 1 call, got %d", len(got))
	}
}

func TestNotifyPushFailSends(t *testing.T) {
	hook := newWebhookRecorder(t)
	fake := writeFakeSSH(t, `cat >/dev/null; echo "connection refused" 1>&2; exit 255`)
	srv := notifyServer(t, hook, func(c *config.ServerConfig) {
		c.Push = config.PushConfig{
			Enabled:        true,
			TimeoutSeconds: 5,
			Targets: []config.PushTarget{{
				Name: "test-vps", User: "nftauth", Host: "203.0.113.10", Port: 2222,
				IdentityFile: "/root/.ssh/nft_auth_push_test",
			}},
		}
	})
	srv.pusher.SSHPath = fake

	authSuccess(t, srv)
	srv.notify.wait()

	var events []string
	for _, b := range hook.all() {
		var ev struct {
			Event string `json:"event"`
		}
		_ = json.Unmarshal([]byte(b), &ev)
		events = append(events, ev.Event)
	}
	joined := strings.Join(events, ",")
	if !strings.Contains(joined, "push.fail") {
		t.Fatalf("push failure must notify, got events %q", joined)
	}
}

func TestNotifyTelegramPayloadShape(t *testing.T) {
	hook := newWebhookRecorder(t)
	srv, _ := testServer(t, func(c *config.ServerConfig) {
		c.Notify = config.NotifyConfig{
			WebhookURL:     hook.ts.URL,
			TelegramChatID: "810981110",
			TimeoutSeconds: 5,
		}
	})

	if rec := authSuccess(t, srv); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	srv.notify.wait()

	got := hook.all()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 webhook call, got %d", len(got))
	}
	var msg struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal([]byte(got[0]), &msg); err != nil {
		t.Fatalf("telegram body is not JSON: %v", err)
	}
	if msg.ChatID != "810981110" {
		t.Fatalf("chat_id = %q, want 810981110", msg.ChatID)
	}
	if !strings.Contains(msg.Text, "entry.new") || !strings.Contains(msg.Text, "1.2.3.4/32") {
		t.Fatalf("text must contain the event and cidr, got %q", msg.Text)
	}
	if strings.Contains(got[0], `"event"`) {
		t.Fatal("telegram payload must not use the generic shape")
	}
}

func TestNotifyDisabledSendsNothing(t *testing.T) {
	srv, _ := testServer(t, nil) // notify not configured
	if rec := authSuccess(t, srv); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	srv.notify.wait() // must not hang or panic with an empty URL
}

func TestNotifyFailureNeverLogsWebhookURL(t *testing.T) {
	// Point the webhook at a closed port so the send fails, then make sure the
	// audit log records notify.fail without leaking the URL (it may embed a
	// bot token).
	srv, buf := testServer(t, func(c *config.ServerConfig) {
		c.Notify = config.NotifyConfig{WebhookURL: "http://127.0.0.1:1/hook-token-abc", TimeoutSeconds: 1}
	})
	authSuccess(t, srv)
	srv.notify.wait()

	a := buf.String()
	if !strings.Contains(a, "notify.fail") {
		t.Fatalf("audit must record notify.fail, got %s", a)
	}
	if strings.Contains(a, "hook-token-abc") || strings.Contains(a, "127.0.0.1:1") {
		t.Fatalf("audit must never contain the webhook URL, got %s", a)
	}
}
