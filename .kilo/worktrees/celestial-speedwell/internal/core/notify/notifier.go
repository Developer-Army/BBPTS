// Package notify provides multi-channel notification capabilities for BBPTS.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config holds the notification credentials.
type Config struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
	DiscordWebhook   string `json:"discord_webhook"`
	SlackWebhook     string `json:"slack_webhook"`
}

// Finding is a structured high-priority alert payload derived from scan results.
type Finding struct {
	Host     string
	Priority string
	Score    int
	Tags     []string
	Reasons  []string
}

// Notifier handles sending messages to various platforms.
type Notifier struct {
	cfg        Config
	httpClient *http.Client
}

// NewNotifier creates a new instance of Notifier.
func NewNotifier(cfg Config) *Notifier {
	return &Notifier{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendMessage sends a plain text message to all enabled channels.
func (n *Notifier) SendMessage(msg string) error {
	var errors []error

	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscord(msg); err != nil {
			errors = append(errors, fmt.Errorf("discord error: %w", err))
		}
	}

	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegram(msg); err != nil {
			errors = append(errors, fmt.Errorf("telegram error: %w", err))
		}
	}

	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlack(msg); err != nil {
			errors = append(errors, fmt.Errorf("slack error: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %v", errors)
	}
	return nil
}

// SendAlert formats a finding into a concise message and dispatches it.
func (n *Notifier) SendAlert(_ context.Context, finding Finding) error {
	parts := []string{
		fmt.Sprintf("Host: %s", finding.Host),
		fmt.Sprintf("Priority: %s", finding.Priority),
		fmt.Sprintf("Score: %d", finding.Score),
	}
	if len(finding.Tags) > 0 {
		parts = append(parts, fmt.Sprintf("Tags: %s", strings.Join(finding.Tags, ", ")))
	}
	if len(finding.Reasons) > 0 {
		parts = append(parts, fmt.Sprintf("Reasons: %s", strings.Join(finding.Reasons, "; ")))
	}
	return n.SendMessage(strings.Join(parts, "\n"))
}

// sendDiscord sends a message via Discord Webhook.
func (n *Notifier) sendDiscord(msg string) error {
	payload := map[string]string{
		"content": fmt.Sprintf("🚀 **BBPTS Alert**\n%s", msg),
	}
	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

// sendTelegram sends a message via Telegram Bot API.
func (n *Notifier) sendTelegram(msg string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)
	payload := map[string]string{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       fmt.Sprintf("🚀 BBPTS Alert\n\n%s", msg),
		"parse_mode": "Markdown",
	}
	return n.postJSON(url, payload)
}

// sendSlack sends a message via Slack Webhook.
func (n *Notifier) sendSlack(msg string) error {
	payload := map[string]string{
		"text": fmt.Sprintf("🚀 *BBPTS Alert*\n%s", msg),
	}
	return n.postJSON(n.cfg.SlackWebhook, payload)
}

func (n *Notifier) postJSON(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := n.httpClient.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
