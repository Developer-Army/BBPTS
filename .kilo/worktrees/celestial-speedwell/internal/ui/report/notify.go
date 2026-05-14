// Package report implements webhook-based alerting for BBPTS.
// Supports Telegram, Discord, and Slack. Sends a formatted "Delta Report"
// after every scan so you get alerted while sleeping.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/core/state"
	"github.com/Developer-Army/BBPTS/internal/engine/rules"
)

// NotifyConfig holds webhook URLs for each notification channel.
type NotifyConfig struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
	DiscordWebhook   string `json:"discord_webhook"`
	SlackWebhook     string `json:"slack_webhook"`
}

// Notifier sends alerts over configured channels.
type Notifier struct {
	cfg        NotifyConfig
	httpClient *http.Client
}

// NewNotifier creates a new Notifier.
func NewNotifier(cfg NotifyConfig) *Notifier {
	return &Notifier{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsConfigured returns true if at least one notification channel is configured.
func (n *Notifier) IsConfigured() bool {
	return (n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "") ||
		n.cfg.DiscordWebhook != "" ||
		n.cfg.SlackWebhook != ""
}

// New creates a new Notifier (alias kept for internal use).
func New(cfg NotifyConfig) *Notifier {
	return NewNotifier(cfg)
}

// SendDiff fires a scan delta report to all configured channels.
func (n *Notifier) SendDiff(ctx context.Context, scope string, diff *state.Diff) error {
	if diff == nil {
		return nil
	}
	if len(diff.NewTargets) == 0 && len(diff.NewEvents) == 0 {
		slog.Debug("no new findings, skipping notification")
		return nil
	}

	msg := formatDiffMessage(scope, diff)

	var errs []string
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegram(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("telegram: %v", err))
		}
	}
	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscord(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("discord: %v", err))
		}
	}
	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlack(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("slack: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SendRuleMatches fires high/critical rule match alerts immediately.
func (n *Notifier) SendRuleMatches(ctx context.Context, scope string, matches []rules.Match) error {
	criticals := filterByPriority(matches, "critical", "high")
	if len(criticals) == 0 {
		return nil
	}

	msg := formatRuleMatchMessage(scope, criticals)

	var errs []string
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegram(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("telegram: %v", err))
		}
	}
	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscord(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("discord: %v", err))
		}
	}
	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlack(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("slack: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *Notifier) sendTelegram(ctx context.Context, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)
	payload := map[string]string{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	return n.postJSON(ctx, url, payload)
}

func (n *Notifier) sendDiscord(ctx context.Context, text string) error {
	payload := map[string]string{"content": text}
	return n.postJSON(ctx, n.cfg.DiscordWebhook, payload)
}

func (n *Notifier) sendSlack(ctx context.Context, text string) error {
	payload := map[string]string{"text": text}
	return n.postJSON(ctx, n.cfg.SlackWebhook, payload)
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func formatDiffMessage(scope string, diff *state.Diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔍 *BBPTS Scan Alert — %s*\n", scope)
	fmt.Fprintf(&b, "📅 `%s`\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	if len(diff.NewTargets) > 0 {
		fmt.Fprintf(&b, "🆕 *%d New Targets*\n", len(diff.NewTargets))
		for i, t := range diff.NewTargets {
			if i >= 10 {
				fmt.Fprintf(&b, "  ...and %d more\n", len(diff.NewTargets)-10)
				break
			}
			fmt.Fprintf(&b, "  • `%s`\n", t)
		}
		b.WriteString("\n")
	}

	if len(diff.NewEvents) > 0 {
		fmt.Fprintf(&b, "🎯 *%d New Events*\n", len(diff.NewEvents))
		for i, ev := range diff.NewEvents {
			if i >= 10 {
				fmt.Fprintf(&b, "  ...and %d more\n", len(diff.NewEvents)-10)
				break
			}
			fmt.Fprintf(&b, "  • `[%s]` %s\n", ev.Source, ev.Target)
		}
	}

	return b.String()
}

func formatRuleMatchMessage(scope string, matches []rules.Match) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 *BBPTS Critical Alert — %s*\n", scope)
	fmt.Fprintf(&b, "📅 `%s`\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "*%d High/Critical Rule Matches*\n\n", len(matches))

	for i, m := range matches {
		if i >= 15 {
			fmt.Fprintf(&b, "...and %d more matches\n", len(matches)-15)
			break
		}
		emoji := "⚠️"
		if m.Rule.Priority == "critical" {
			emoji = "🔥"
		}
		fmt.Fprintf(&b, "%s *[%s]* %s\n", emoji, m.Rule.Priority, m.Rule.Description)
		fmt.Fprintf(&b, "   `%s`\n", m.Event.Target)
		if m.Rule.Action.Message != "" {
			fmt.Fprintf(&b, "   _%s_\n", m.Rule.Action.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func filterByPriority(matches []rules.Match, priorities ...string) []rules.Match {
	set := make(map[string]struct{})
	for _, p := range priorities {
		set[p] = struct{}{}
	}
	var filtered []rules.Match
	for _, m := range matches {
		if _, ok := set[m.Rule.Priority]; ok {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
