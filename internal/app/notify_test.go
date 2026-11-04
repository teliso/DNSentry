package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type sentMessages struct {
	mu   sync.Mutex
	list []notification
	to   []string
}

func (s *sentMessages) record(_ context.Context, hook WebhookConfig, n notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, n)
	s.to = append(s.to, hook.Name)
	return nil
}

func (s *sentMessages) wait(t *testing.T, count int) []notification {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.list) >= count {
			defer s.mu.Unlock()
			return append([]notification(nil), s.list...)
		}
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("expected %d notifications, got %d: %+v", count, len(s.list), s.list)
	return nil
}

func (s *sentMessages) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.list)
}

func TestNotifierAnnouncesProblemsOnceAndRecoveryAfterConfirmation(t *testing.T) {
	var current []problem
	config := NotificationsConfig{Webhooks: []WebhookConfig{{Name: "phone", URL: "http://x.test/", Enabled: true}, {Name: "off", URL: "http://y.test/", Enabled: false}}}
	notifier := newNotifier(func() NotificationsConfig { return config }, func(time.Time) []problem { return current })
	sent := &sentMessages{}
	notifier.send = sent.record
	ctx := context.Background()
	now := time.Now()

	notifier.check(ctx, now) // nothing wrong
	current = []problem{{ID: "upstreams-down", Category: notifyUpstream, Title: "down", Detail: "details"}}
	notifier.check(ctx, now)
	time.Sleep(30 * time.Millisecond)
	if sent.count() != 0 {
		t.Fatal("a problem seen once must not be announced yet (it may be a blip)")
	}
	notifier.check(ctx, now)
	messages := sent.wait(t, 1)
	if messages[0].Event != "problem" || messages[0].Title != "down" || sent.to[0] != "phone" {
		t.Fatalf("problem message = %+v to %v", messages[0], sent.to)
	}
	notifier.check(ctx, now) // still down: no repeat
	time.Sleep(30 * time.Millisecond)
	if sent.count() != 1 {
		t.Fatalf("a persisting problem was announced again: %d", sent.count())
	}

	current = nil
	notifier.check(ctx, now)
	messages = sent.wait(t, 2)
	if messages[1].Event != "recovered" || !strings.HasPrefix(messages[1].Title, "已恢复") {
		t.Fatalf("recovery message = %+v", messages[1])
	}

	// A blip that clears before it is confirmed is never announced.
	current = []problem{{ID: "blip", Category: notifyUpstream, Title: "blip"}}
	notifier.check(ctx, now)
	current = nil
	notifier.check(ctx, now)
	time.Sleep(30 * time.Millisecond)
	if sent.count() != 2 {
		t.Fatalf("a blip was announced: %d", sent.count())
	}
}

func TestNotifierHonoursTheEventSelection(t *testing.T) {
	current := []problem{
		{ID: "upstreams-down", Category: notifyUpstream, Title: "up"},
		{ID: "source-x", Category: notifyRuleSource, Title: "src"},
	}
	config := NotificationsConfig{Webhooks: []WebhookConfig{{Name: "h", URL: "http://x.test/", Enabled: true}}, Events: []string{notifyRuleSource}}
	notifier := newNotifier(func() NotificationsConfig { return config }, func(time.Time) []problem { return current })
	sent := &sentMessages{}
	notifier.send = sent.record
	for i := 0; i < notifyConfirmAfter; i++ {
		notifier.check(context.Background(), time.Now())
	}
	messages := sent.wait(t, 1)
	time.Sleep(30 * time.Millisecond)
	if len(messages) != 1 || messages[0].ID != "source-x" || sent.count() != 1 {
		t.Fatalf("only rule source problems were selected: %+v", messages)
	}
}

func TestSendWebhookFormats(t *testing.T) {
	type received struct {
		contentType, title, tags, body string
	}
	got := make(chan received, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Get("Content-Type"), r.Header.Get("Title"), r.Header.Get("Tags"), string(body)}
	}))
	defer server.Close()
	message := notification{Event: "problem", ID: "upstreams-down", Title: "所有上游 DNS 服务器都没有响应", Message: "details", Time: time.Unix(1700000000, 0)}

	if err := sendWebhook(context.Background(), WebhookConfig{URL: server.URL, Format: webhookJSON}, message); err != nil {
		t.Fatal(err)
	}
	r := <-got
	var payload map[string]string
	if err := json.Unmarshal([]byte(r.body), &payload); err != nil || r.contentType != "application/json" {
		t.Fatalf("json body %q: %v", r.body, err)
	}
	for key, want := range map[string]string{"event": "problem", "id": "upstreams-down", "title": message.Title, "message": "details", "time": "2023-11-14T22:13:20Z"} {
		if payload[key] != want {
			t.Errorf("%s = %q, want %q", key, payload[key], want)
		}
	}
	if payload["text"] != payload["content"] || !strings.Contains(payload["text"], message.Title) || !strings.Contains(payload["text"], "details") {
		t.Errorf("text/content = %q / %q", payload["text"], payload["content"])
	}

	if err := sendWebhook(context.Background(), WebhookConfig{URL: server.URL, Format: webhookPlain}, notification{Event: "test", Title: "DNSentry test", Message: "hello", Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r = <-got
	if r.body != "hello" || !strings.HasPrefix(r.contentType, "text/plain") || r.title != "DNSentry test" || r.tags != "bell" {
		t.Fatalf("plain = %+v", r)
	}
}

func TestSendWebhookReportsFailuresAndDoesNotFollowRedirects(t *testing.T) {
	target := make(chan struct{}, 1)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { target <- struct{}{} }))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer redirecting.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusInternalServerError) }))
	defer failing.Close()

	if err := sendWebhook(context.Background(), WebhookConfig{URL: redirecting.URL}, notification{Title: "x"}); err == nil {
		t.Fatal("a redirect is not a success")
	}
	select {
	case <-target:
		t.Fatal("the redirect was followed")
	case <-time.After(100 * time.Millisecond):
	}
	if err := sendWebhook(context.Background(), WebhookConfig{URL: failing.URL}, notification{Title: "x"}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("server error = %v", err)
	}
	if err := sendWebhook(context.Background(), WebhookConfig{URL: "file:///etc/passwd"}, notification{Title: "x"}); err == nil {
		t.Fatal("a non-http URL was accepted")
	}
}

func TestValidateNotifications(t *testing.T) {
	good := NotificationsConfig{Webhooks: []WebhookConfig{{Name: " phone ", URL: " https://ntfy.sh/topic ", Format: " PLAIN ", Enabled: true}, {URL: "http://192.168.1.5:8080/hook"}}, Events: []string{"UPSTREAM", "upstream", "rule_source"}}
	if err := validateNotifications(&good); err != nil {
		t.Fatal(err)
	}
	if good.Webhooks[0].Name != "phone" || good.Webhooks[0].URL != "https://ntfy.sh/topic" || good.Webhooks[0].Format != "plain" || good.Webhooks[1].Format != "json" || len(good.Events) != 2 {
		t.Fatalf("not normalised: %+v", good)
	}
	for name, config := range map[string]NotificationsConfig{
		"bad scheme":   {Webhooks: []WebhookConfig{{URL: "ftp://x.test/"}}},
		"no host":      {Webhooks: []WebhookConfig{{URL: "https:///path"}}},
		"empty":        {Webhooks: []WebhookConfig{{URL: ""}}},
		"bad format":   {Webhooks: []WebhookConfig{{URL: "http://x.test/", Format: "xml"}}},
		"unknown kind": {Events: []string{"everything"}},
		"too many":     {Webhooks: make([]WebhookConfig, maxWebhooks+1)},
	} {
		if err := validateNotifications(&config); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	var none NotificationsConfig
	if !none.IsZero() || (NotificationsConfig{Events: []string{"upstream"}}).IsZero() {
		t.Fatal("IsZero")
	}
}

func TestNotificationTestEndpoint(t *testing.T) {
	received := make(chan string, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
	}))
	defer hook.Close()
	api := newConfigTestAPI(t)
	if response := callAPI(t, api, http.MethodPost, "/api/notifications/test", map[string]any{"url": hook.URL, "format": "json"}); response.Code != http.StatusOK {
		t.Fatalf("test = %d %s", response.Code, response.Body)
	}
	if body := <-received; !strings.Contains(body, `"event":"test"`) {
		t.Fatalf("body = %s", body)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/notifications/test", map[string]any{"url": "ftp://x"}); response.Code != http.StatusBadRequest {
		t.Fatalf("bad url = %d", response.Code)
	}
	if response := callAPI(t, api, http.MethodPost, "/api/notifications/test", map[string]any{"url": "http://127.0.0.1:1/"}); response.Code != http.StatusBadGateway {
		t.Fatalf("unreachable = %d", response.Code)
	}
}

func TestNotificationsAreSavedInTheConfiguration(t *testing.T) {
	config := testConfig()
	if data, _ := yaml.Marshal(newYAMLConfig(config)); strings.Contains(string(data), "notifications") {
		t.Fatal("an unused notifications section must not be written")
	}
	config.Notifications = NotificationsConfig{Webhooks: []WebhookConfig{{Name: "n", URL: "https://ntfy.sh/x", Format: "plain", Enabled: true}}}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := yaml.Marshal(newYAMLConfig(validated))
	if !strings.Contains(string(data), "https://ntfy.sh/x") {
		t.Fatalf("webhook not written:\n%s", data)
	}
}

func TestCollectProblemsSeesUpstreamsThatAreAllDown(t *testing.T) {
	api := newConfigTestAPI(t)
	collect := collectProblems(api.resolver, api.updater)
	if got := collect(time.Now()); len(got) != 0 {
		t.Fatalf("a healthy setup reported problems: %+v", got)
	}
	for _, address := range api.resolver.configSnapshot().Upstreams {
		for i := 0; i < 5; i++ {
			api.resolver.pool.RecordFailure(address)
		}
	}
	got := collect(time.Now())
	if len(got) != 1 || got[0].ID != "upstreams-down" || got[0].Category != notifyUpstream {
		t.Fatalf("problems = %+v", got)
	}
}
