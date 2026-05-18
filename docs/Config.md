# Configuration Guide - BBPTS v1.1

This guide covers BBPTS configuration options, API keys, and customization.

## Table of Contents

- [Configuration Files](#configuration-files)
- [Main Configuration](#main-configuration)
- [Rules Configuration](#rules-configuration)
- [API Keys](#api-keys)
- [Environment Variables](#environment-variables)
- [Docker Configuration](#docker-configuration)
- [Advanced Options](#advanced-options)
- [Tool presets and program profiles](#tool-presets-and-program-profiles)

## Configuration Files

BBPTS uses two main configuration files:

- `configs/config.json` - Main application settings
- `configs/rules.json` - Custom event-matching rules

## Main Configuration

### Basic Configuration

```json
{
  "rate_limit": 20,
  "threads": 32,
  "state_dir": "./results/state",
  "wordlists_dir": "./wordlists",
  "submit": {
    "platform": ""
  }
}
```

The CLI `-timeout` flag controls the global scan timeout. Its default is `0`, which disables the global timeout and leaves cancellation to per-tool contexts or the operator.

### Notification Configuration

```json
{
  "notify": {
    "telegram_bot_token": "your-telegram-bot-token",
    "telegram_chat_id": "your-chat-id",
    "discord_webhook": "https://discord.com/api/webhooks/...",
    "slack_webhook": "https://hooks.slack.com/services/..."
  }
}
```

### Fleet Configuration

```json
{
  "fleet": {
    "enabled": false,
    "fleet_name": "bbpts-fleet",
    "fleet_size": 10,
    "delete_after": true
  }
}
```

## Rules Configuration

### Basic Rules Structure

```json
{
  "rules": [
    {
      "name": "High-Value Subdomain",
      "description": "Flag high-value subdomains for priority testing",
      "condition": {
        "field": "target",
        "operator": "contains",
        "value": "admin"
      },
      "action": {
        "type": "tag",
        "tag": "high-value"
      }
    }
  ]
}
```

### Rule Conditions

#### Field Operators

- `target` - The discovered target/URL
- `source` - Tool that discovered the target
- `type` - Event type
- `properties` - Event properties map

#### Operators

- `equals` - Exact string match
- `contains` - Substring match
- `starts_with` - Prefix match
- `ends_with` - Suffix match
- `regex` - Regular expression match

### Rule Actions

#### Tag Action

```json
{
  "action": {
    "type": "tag",
    "tag": "custom-tag"
  }
}
```

#### Score Action

```json
{
  "action": {
    "type": "score",
    "score": 25
  }
}
```

#### Priority Action

```json
{
  "action": {
    "type": "priority",
    "priority": "high"
  }
}
```

## API Keys

### Supported Services

BBPTS supports API keys for enhanced reconnaissance:

```json
{
  "api_keys": {
    "shodan": "your-shodan-api-key",
    "censys": "your-censys-api-id:secret",
    "securitytrails": "your-securitytrails-key",
    "github": "your-github-personal-access-token",
    "chaos": "your-chaos-api-key",
    "virustotal": "your-virustotal-api-key",
    "passivetotal": "your-passivetotal-username:password",
    "binaryedge": "your-binaryedge-api-key"
  }
}
```

### Obtaining API Keys

#### Shodan
1. Visit [Shodan](https://account.shodan.io/)
2. Sign up for a free account
3. Get your API key from the dashboard

#### Censys
1. Visit [Censys](https://censys.io/)
2. Create an account
3. Generate API ID and Secret

#### GitHub
1. Go to GitHub Settings > Developer settings > Personal access tokens
2. Generate a new token with `public_repo` scope

#### VirusTotal
1. Visit [VirusTotal](https://www.virustotal.com/)
2. Sign up and get your API key

### Security Notes

- Store API keys securely
- Use environment variables for sensitive keys
- Rotate keys regularly
- Monitor API usage to avoid rate limits

## Wordlist Configuration

BBPTS supports tool-specific wordlist configuration for optimal performance:

### Wordlist Types

```json
{
  "wordlists": {
    "dns": "dns-5k.txt",
    "directory": "raft-small-files.txt",
    "subdomain": "subdomains-top1million-5000.txt",
    "api": "api-endpoints.txt"
  }
}
```

### Wordlist Descriptions

- **dns**: Used by DNS resolution tools (dnsx) - defaults to 5k entries for fast scanning
- **directory**: Used by content discovery tools (gobuster, ffuf) - defaults to raft-small-files for common paths
- **subdomain**: Used by subdomain enumeration tools (amass) - defaults to top 5k subdomains
- **api**: Used by API discovery tools - defaults to common API endpoints

### Custom Wordlists

You can specify custom wordlists by providing the filename:

```json
{
  "wordlists": {
    "dns": "my-custom-dns.txt",
    "directory": "my-big-directory-list.txt",
    "subdomain": "my-subdomain-list.txt",
    "api": "my-api-endpoints.txt"
  }
}
```

Wordlists are stored in the `wordlists_dir` directory. The setup script automatically downloads default wordlists.

## Environment Variables

BBPTS supports environment variable overrides:

```bash
# API Keys
export BBPTS_SHODAN_API_KEY="your-key"
export BBPTS_CENSYS_API_ID="your-id"
export BBPTS_CENSYS_API_SECRET="your-secret"

# Configuration
export BBPTS_RATE_LIMIT="50"
export BBPTS_THREADS="64"
export BBPTS_TIMEOUT="60s"

# Notifications
export BBPTS_TELEGRAM_BOT_TOKEN="your-token"
export BBPTS_TELEGRAM_CHAT_ID="your-chat-id"
export BBPTS_DISCORD_WEBHOOK="your-webhook-url"
```

### Precedence

Configuration values are loaded in this order (last wins):

1. Default values
2. `configs/config.json`
3. Environment variables
4. Command-line flags

## Docker Configuration

### Basic Docker Run

```bash
docker run -it \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/configs:/app/configs \
  bbpts -i targets.txt
```

### With API Keys

```bash
docker run -it \
  -e BBPTS_SHODAN_API_KEY="your-key" \
  -v $(pwd)/results:/app/results \
  bbpts -i targets.txt
```

### Custom Configuration

```bash
docker run -it \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/wordlists:/app/wordlists \
  bbpts -config /app/configs/custom.json -i targets.txt
```

## Advanced Options

### Performance Tuning

```json
{
  "threads": 64,
  "rate_limit": 100,
  "timeout": "45s",
  "low_resource": false
}
```

### Custom Wordlists

```json
{
  "wordlists_dir": "/path/to/custom/wordlists"
}
```

### State Management

```json
{
  "state_dir": "/persistent/state/directory"
}
```

### Proxy Configuration

```json
{
  "proxies": [
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080"
  ]
}
```

## Tool presets and program profiles

Use **`tool_presets`** for repeatable one-flag workflows (`-preset <name>` when you omit `-tools`). Preset entries may include `tools`, `timeout` (Go duration string), and `rate_limit`.

Use **`program_profiles`** for bounty-specific defaults and exclusions. Reference a profile with `-profile <name>`. Hosts listed in `exclude_hosts` (exact, case-insensitive) or suffix-matched via `exclude_suffix` are removed before reconnaissance. Optional `tools`, `rate_limit`, and `timeout` apply when `-tools` is omitted (same precedence as presets: if both `-preset` and `-profile` are set, the preset’s tool list wins).

Example fragment:

```json
{
  "tool_presets": {
    "passive": {
      "tools": "subfinder,crtsh,httpx,dnsx",
      "timeout": "60s",
      "rate_limit": 15
    },
    "deep": {
      "tools": "subfinder,httpx,katana,nuclei,ffuf",
      "timeout": "120s",
      "rate_limit": 10
    }
  },
  "program_profiles": {
    "acme_scope": {
      "tools": "crtsh,subfinder,httpx",
      "rate_limit": 12,
      "exclude_hosts": ["legacy-out-of-scope.example.com"],
      "exclude_suffix": [".corp.internal"]
    }
  }
}
```

### Evidence bundle

Pass `-evidence path/to/evidence.json` to write a compact JSON file of the top insights (sorted by score, then confidence). Use `-evidence-top N` to cap the number of entries (default 25).

## Troubleshooting

### Common Configuration Issues

**Configuration not loading:**
- Check file permissions
- Verify JSON syntax
- Use absolute paths

**API keys not working:**
- Verify key format
- Check account status
- Monitor rate limits

**Performance issues:**
- Adjust thread counts
- Increase timeouts
- Use low-resource mode

**State persistence:**
- Ensure write permissions on state directory
- Check disk space
- Verify file system compatibility

## Examples

### Complete Configuration

```json
{
  "rate_limit": 30,
  "threads": 48,
  "timeout": "35s",
  "state_dir": "./state",
  "wordlists_dir": "./wordlists",
  "wordlists": {
    "dns": "dns-5k.txt",
    "directory": "raft-small-files.txt",
    "subdomain": "subdomains-top1million-5000.txt",
    "api": "api-endpoints.txt"
  },
  "api_keys": {
    "shodan": "your-shodan-key",
    "github": "your-github-token"
  },
  "notify": {
    "discord_webhook": "https://discord.com/api/webhooks/...",
    "slack_webhook": "https://hooks.slack.com/services/..."
  },
  "fleet": {
    "enabled": false
  }
}
```

### Minimal Configuration

```json
{
  "threads": 16,
  "rate_limit": 10
}
```

This configuration guide provides comprehensive control over BBPTS behavior and integration capabilities.
