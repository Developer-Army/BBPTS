package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func RunWizard(path string) error {
	reader := bufio.NewReader(os.Stdin)
	cfg := DefaultConfig()

	if cfg.APIKeys == nil {
		cfg.APIKeys = make(map[string]string)
	}

	fmt.Println("========================================")
	fmt.Println("      BBPTS Configuration Wizard        ")
	fmt.Println("========================================")
	fmt.Println("Press Enter to keep default values [in brackets]")
	fmt.Println()

	fmt.Printf("Default Concurrency Threads [%d]: ", cfg.Threads)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		if val, err := strconv.Atoi(input); err == nil && val > 0 {
			cfg.Threads = val
		}
	}

	fmt.Printf("Global Rate Limit (req/sec) [%d]: ", cfg.RateLimit)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		if val, err := strconv.Atoi(input); err == nil && val >= 0 {
			cfg.RateLimit = val
		}
	}

	apiKeys := []string{"shodan", "securitytrails", "github", "chaos", "virustotal", "passivetotal", "binaryedge"}
	fmt.Println("\n--- API Keys (Optional) ---")
	for _, provider := range apiKeys {
		current := cfg.APIKeys[provider]
		fmt.Printf("%s API Key [%s]: ", title(provider), current)
		input, _ = reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			cfg.APIKeys[provider] = input
		}
	}

	fmt.Println("\n--- Notification Webhooks (Optional) ---")

	fmt.Printf("Telegram Bot Token [%s]: ", cfg.Notify.TelegramBotToken)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Notify.TelegramBotToken = input
	}

	fmt.Printf("Telegram Chat ID [%s]: ", cfg.Notify.TelegramChatID)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Notify.TelegramChatID = input
	}

	fmt.Printf("Discord Webhook URL [%s]: ", cfg.Notify.DiscordWebhook)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Notify.DiscordWebhook = input
	}

	fmt.Printf("Slack Webhook URL [%s]: ", cfg.Notify.SlackWebhook)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Notify.SlackWebhook = input
	}

	fmt.Println("\n--- Bug Bounty Platform Integration ---")
	fmt.Printf("Submit Platform (e.g. hackerone, bugcrowd) [%s]: ", cfg.Submit.Platform)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Submit.Platform = input
	}

	fmt.Println("\n--- Distributed Fleet (Axiom) ---")
	fmt.Printf("Enable Fleet (true/false) [%t]: ", cfg.Fleet.Enabled)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Fleet.Enabled = (strings.ToLower(input) == "true" || strings.ToLower(input) == "t" || input == "1")
	}

	fmt.Printf("Fleet Name [%s]: ", cfg.Fleet.FleetName)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Fleet.FleetName = input
	}

	fmt.Printf("Fleet Size [%d]: ", cfg.Fleet.FleetSize)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		if val, err := strconv.Atoi(input); err == nil && val > 0 {
			cfg.Fleet.FleetSize = val
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("\nConfig successfully written to %s\n", path)
	return nil
}

func title(s string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.ToUpper(s[0:1]) + s[1:]
}
