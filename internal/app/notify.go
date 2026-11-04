package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/teliso/DNSentry/internal/buildinfo"
	"github.com/teliso/DNSentry/internal/rules"
)

// Notifications tell the administrator about problems when nobody has the
// console open: upstream servers that stopped answering and rule lists that
// stopped updating. A problem is announced once it has persisted for a minute,
// and again when it is gone. Messages go to webhooks (a JSON body that
// Slack-, Discord- and Gotify-style endpoints accept, or plain text for ntfy).

const (
	notifyUpstream   = "upstream"
	notifyRuleSource = "rule_source"

	webhookJSON  = "json"
	webhookPlain = "plain"

	maxWebhooks        = 8
	notifyCheckEvery   = 30 * time.Second
	notifyConfirmAfter = 2 // consecutive checks before a problem is announced
	webhookTimeout     = 10 * time.Second
)

// WebhookConfig is one place to send notifications to.
type WebhookConfig struct {
	Name    string `json:"name" yaml:"name,omitempty"`
	URL     string `json:"url" yaml:"url"`
	Format  string `json:"format" yaml:"format,omitempty"` // "json" (default) or "plain"
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

// NotificationsConfig holds the webhooks and which kinds of problems are sent.
type NotificationsConfig struct {
	Webhooks []WebhookConfig `json:"webhooks" yaml:"webhooks,omitempty"`
	// Events limits the kinds of problems ("upstream", "rule_source"); empty means all.
	Events []string `json:"events" yaml:"events,omitempty"`
}

// IsZero keeps an unused section out of the configuration file.
func (c NotificationsConfig) IsZero() bool { return len(c.Webhooks) == 0 && len(c.Events) == 0 }

func (c NotificationsConfig) wants(category string) bool {
	if len(c.Events) == 0 {
		return true
	}
	for _, event := range c.Events {
		if event == category {
			return true
		}
	}
	return false
}

func validateNotifications(config *NotificationsConfig) error {
	if len(config.Webhooks) > maxWebhooks {
		return fmt.Errorf("notifications: at most %d webhooks", maxWebhooks)
	}
	for index := range config.Webhooks {
		hook := &config.Webhooks[index]
		hook.Name = strings.TrimSpace(hook.Name)
		hook.URL = strings.TrimSpace(hook.URL)
		hook.Format = strings.ToLower(strings.TrimSpace(hook.Format))
		if hook.Format == "" {
			hook.Format = webhookJSON
		}
		if hook.Format != webhookJSON && hook.Format != webhookPlain {
			return fmt.Errorf("notifications.webhooks[%d]: format must be json or plain", index)
		}
		if len(hook.Name) > 64 {
			return fmt.Errorf("notifications.webhooks[%d]: name is too long", index)
		}
		if err := validateWebhookURL(hook.URL); err != nil {
			return fmt.Errorf("notifications.webhooks[%d]: %w", index, err)
		}
	}
	events := config.Events[:0]
	seen := map[string]bool{}
	for _, event := range config.Events {
		event = strings.ToLower(strings.TrimSpace(event))
		if event != notifyUpstream && event != notifyRuleSource {
			return fmt.Errorf("notifications: unknown event %q (use %s or %s)", event, notifyUpstream, notifyRuleSource)
		}
		if !seen[event] {
			seen[event] = true
			events = append(events, event)
		}
	}
	config.Events = events
	return nil
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return errors.New("url must be an http:// or https:// address")
	}
	return nil
}

// notification is what is sent.
type notification struct {
	Event   string // "problem", "recovered" or "test"
	ID      string // stable identifier of the problem
	Title   string
	Message string
	Time    time.Time
}

// problem is something currently wrong.
type problem struct {
	ID       string
	Category string
	Title    string
	Detail   string
}

// problemFunc reports what is wrong right now.
type problemFunc func(now time.Time) []problem

type problemState struct {
	seen     int
	notified bool
	problem  problem
}

// Notifier watches for problems and sends notifications.
type Notifier struct {
	config   func() NotificationsConfig
	problems problemFunc
	send     func(ctx context.Context, hook WebhookConfig, n notification) error
	every    time.Duration

	mu     sync.Mutex
	active map[string]*problemState
}

func newNotifier(config func() NotificationsConfig, problems problemFunc) *Notifier {
	return &Notifier{config: config, problems: problems, send: sendWebhook, every: notifyCheckEvery, active: map[string]*problemState{}}
}

// Run checks periodically until ctx is done.
func (n *Notifier) Run(ctx context.Context) {
	ticker := time.NewTicker(n.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.check(ctx, time.Now())
		}
	}
}

// check compares the current problems with the announced ones.
func (n *Notifier) check(ctx context.Context, now time.Time) {
	config := n.config()
	current := map[string]problem{}
	for _, p := range n.problems(now) {
		current[p.ID] = p
	}
	var outgoing []notification
	n.mu.Lock()
	for id, p := range current {
		state := n.active[id]
		if state == nil {
			state = &problemState{}
			n.active[id] = state
		}
		state.problem = p
		state.seen++
		if !state.notified && state.seen >= notifyConfirmAfter {
			state.notified = true
			if config.wants(p.Category) {
				outgoing = append(outgoing, notification{Event: "problem", ID: id, Title: p.Title, Message: p.Detail, Time: now})
			}
		}
	}
	for id, state := range n.active {
		if _, still := current[id]; still {
			continue
		}
		delete(n.active, id)
		if state.notified && config.wants(state.problem.Category) {
			outgoing = append(outgoing, notification{Event: "recovered", ID: id, Title: "已恢复：" + state.problem.Title, Message: "之前的问题已经消失。", Time: now})
		}
	}
	n.mu.Unlock()
	sort.Slice(outgoing, func(i, j int) bool { return outgoing[i].ID < outgoing[j].ID })
	for _, message := range outgoing {
		n.deliver(ctx, config, message)
	}
}

// deliver sends one notification to every enabled webhook, in the background.
func (n *Notifier) deliver(ctx context.Context, config NotificationsConfig, message notification) {
	for _, hook := range config.Webhooks {
		if !hook.Enabled {
			continue
		}
		go func() {
			var err error
			for attempt, wait := 0, 2*time.Second; attempt < 3; attempt, wait = attempt+1, wait*2 {
				if err = n.send(ctx, hook, message); err == nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			slog.Warn("notification could not be delivered", "webhook", hook.Name, "event", message.Event, "error", err)
		}()
	}
}

// collectProblems describes what is wrong with the upstreams and rule sources.
func collectProblems(server *DNSServer, updater *rules.Updater) problemFunc {
	return func(now time.Time) []problem {
		var problems []problem
		health := server.pool.Health()
		if len(health) > 0 {
			down := true
			for _, item := range health {
				down = down && !item.Healthy
			}
			if down {
				problems = append(problems, problem{ID: "upstreams-down", Category: notifyUpstream, Title: "所有上游 DNS 服务器都没有响应", Detail: "没有命中缓存和规则的查询会失败；备用上游（如果配置了）会接管。"})
			}
		}
		for _, route := range server.routeStatus() {
			if len(route.Upstreams) == 0 {
				continue
			}
			down := true
			for _, item := range route.Upstreams {
				down = down && !item.Healthy
			}
			if down {
				name := route.Name
				if name == "" && len(route.Domains) > 0 {
					name = route.Domains[0]
				}
				problems = append(problems, problem{ID: "route-down-" + strings.Join(route.Domains, ","), Category: notifyUpstream, Title: "域名分流“" + name + "”的上游全部没有响应", Detail: "这些域名会解析失败，不会回退到默认上游。"})
			}
		}
		for _, source := range updater.Sources() {
			if !source.Enabled || source.LastError == "" {
				continue
			}
			checked, err := time.Parse(time.RFC3339, source.LastChecked)
			interval := time.Duration(source.IntervalMinutes) * time.Minute
			if err == nil && now.Sub(checked) <= max(24*time.Hour, 2*interval) {
				continue // failing, but still within the normal update gap
			}
			name := source.Name
			if name == "" {
				name = source.URL
			}
			detail := source.LastError
			if source.RuleCount > 0 {
				detail += "（仍在使用缓存的规则）"
			}
			problems = append(problems, problem{ID: "source-" + source.URL, Category: notifyRuleSource, Title: "规则源“" + name + "”长时间没有更新成功", Detail: detail})
		}
		return problems
	}
}

var webhookClient = &http.Client{
	Timeout: webhookTimeout,
	// A webhook answers where it is told to; following redirects would let it
	// bounce the request somewhere else.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func hostLabel() string {
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "dnsentry"
}

// sendWebhook posts n to hook.
func sendWebhook(ctx context.Context, hook WebhookConfig, n notification) error {
	if err := validateWebhookURL(hook.URL); err != nil {
		return err
	}
	text := n.Title
	if n.Message != "" {
		text += "\n" + n.Message
	}
	var body []byte
	headers := map[string]string{}
	switch hook.Format {
	case webhookPlain:
		body = []byte(n.Message)
		if n.Message == "" {
			body = []byte(n.Title)
		}
		headers["Content-Type"] = "text/plain; charset=utf-8"
		headers["Title"] = asciiHeader(n.Title)
		headers["Tags"] = map[string]string{"problem": "warning", "recovered": "white_check_mark", "test": "bell"}[n.Event]
	default:
		payload, err := json.Marshal(map[string]any{
			"event": n.Event, "id": n.ID, "title": n.Title, "message": n.Message, "time": n.Time.UTC().Format(time.RFC3339),
			"instance": hostLabel(), "version": buildinfo.String(),
			// Slack and Mattermost read "text", Discord reads "content", Gotify reads "title" and "message".
			"text": text, "content": text,
		})
		if err != nil {
			return err
		}
		body = payload
		headers["Content-Type"] = "application/json"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "DNSentry/"+buildinfo.String())
	for key, value := range headers {
		if value != "" {
			request.Header.Set(key, value)
		}
	}
	response, err := webhookClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("the webhook answered %s", response.Status)
	}
	return nil
}

// asciiHeader keeps header values to printable ASCII (HTTP headers are not
// meant for Chinese text; ntfy shows the message body anyway).
func asciiHeader(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r >= 0x20 && r < 0x7f {
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

// testNotification serves POST /notifications/test with {"url", "format", "name"}:
// it sends a test message to that webhook and reports whether it was accepted.
func (a *API) testNotification(writer http.ResponseWriter, request *http.Request) {
	var hook WebhookConfig
	if !decodeJSON(writer, request, &hook, "invalid request") {
		return
	}
	check := NotificationsConfig{Webhooks: []WebhookConfig{hook}}
	if err := validateNotifications(&check); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), webhookTimeout+time.Second)
	defer cancel()
	message := notification{Event: "test", ID: "test", Title: "DNSentry 测试通知", Message: "如果你看到这条消息，通知设置是正确的。", Time: time.Now()}
	if err := sendWebhook(ctx, check.Webhooks[0], message); err != nil {
		writeError(writer, http.StatusBadGateway, "could not send the test message: "+err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "sent"})
}
