# Contributing to BBPTS v1.1

Thank you for your interest in contributing to BBPTS! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## Getting Started

### Prerequisites

- Go 1.22 or later
- Git
- Basic knowledge of security testing concepts

### Setup

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/BBPTS.git
   cd BBPTS
   ```

3. Set up the development environment:
   ```bash
   go mod download
   bash scripts/setup.sh
   go build -o bbpts ./cmd/bbpts
   ```

4. Verify installation:
   ```bash
   ./bbpts -doctor
   ```

## Development Workflow

### 1. Choose an Issue

- Check the [GitHub Issues](https://github.com/Developer-Army/BBPTS/issues) for open tasks
- Look for issues labeled `good first issue` or `help wanted`
- Comment on the issue to indicate you're working on it

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 3. Make Changes

- Follow the coding standards below
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

Use conventional commit format:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Testing
- `chore:` - Maintenance

### 5. Push and Create PR

```bash
git push origin your-branch-name
```

Then create a Pull Request on GitHub.

## Pull Request Process

### PR Requirements

- [ ] All tests pass
- [ ] Code follows project standards
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] PR description explains the changes
- [ ] No breaking changes without discussion

### PR Template

Please use this template for Pull Requests:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows Go standards
- [ ] Documentation updated
- [ ] Tests pass
- [ ] No new security issues
```

### Review Process

1. Automated checks run (tests, linting)
2. Code review by maintainers
3. Changes requested or approved
4. Merge when approved

## Coding Standards

### Go Standards

- Follow standard Go formatting (`go fmt`)
- Use `gofmt` for consistent style
- Follow Go naming conventions
- Use meaningful variable and function names
- Keep functions small and focused

### Code Structure

```go
// Package comment
package analyze

// Exported types and functions have comments
// Internal types/functions may omit comments if obvious

// Good: Clear, descriptive names
func AnalyzeTarget(target string) (*Insight, error) {
    // Implementation
}

// Bad: Unclear abbreviations
func AnlzTrgt(t string) (*I, error) {
    // Implementation
}
```

### Error Handling

```go
// Good: Explicit error handling
func processTarget(target string) error {
    if target == "" {
        return fmt.Errorf("target cannot be empty")
    }

    result, err := analyze(target)
    if err != nil {
        return fmt.Errorf("failed to analyze target %s: %w", target, err)
    }

    return saveResult(result)
}

// Bad: Ignoring errors
func processTarget(target string) {
    result, _ := analyze(target) // Don't ignore errors
    saveResult(result) // Don't ignore errors
}
```

### Imports

```go
// Good: Grouped imports
import (
    "context"
    "fmt"
    "time"

    "github.com/projectdiscovery/retryablehttp-go"
    "github.com/Developer-Army/BBPTS/internal/core"
)

// Bad: Not grouped
import "context"
import "fmt"
import (
    "github.com/projectdiscovery/retryablehttp-go"
    "time"
)
```

## Testing

### Test Requirements

- All new code must include tests
- Tests should cover happy path and error cases
- Use table-driven tests for multiple scenarios
- Mock external dependencies

### Test Example

```go
func TestAnalyzeTarget(t *testing.T) {
    tests := []struct {
        name     string
        target   string
        expected *Insight
        wantErr  bool
    }{
        {
            name:   "valid target",
            target: "example.com",
            expected: &Insight{
                Host:  "example.com",
                Score: 10,
            },
            wantErr: false,
        },
        {
            name:    "empty target",
            target:  "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := AnalyzeTarget(tt.target)

            if tt.wantErr {
                if err == nil {
                    t.Error("expected error, got nil")
                }
                return
            }

            if err != nil {
                t.Errorf("unexpected error: %v", err)
                return
            }

            if result.Host != tt.expected.Host {
                t.Errorf("expected host %s, got %s", tt.expected.Host, result.Host)
            }
        })
    }
}
```

### Running Tests

```bash
# All tests
go test ./...

# Specific package
go test ./internal/analysis/...

# With coverage
go test -cover ./...

# Race detection
go test -race ./...
```

## Documentation

### Code Documentation

- All exported functions/types must have comments
- Comments should explain purpose and usage
- Use complete sentences
- Update docs when changing functionality

```go
// AnalyzeTarget performs security analysis on a target domain.
// It returns an Insight with risk score, tags, and recommendations.
// The analysis includes subdomain discovery, technology fingerprinting,
// and vulnerability pattern matching.
func AnalyzeTarget(target string) (*Insight, error) {
    // Implementation
}
```

### User Documentation

- Update README.md for new features
- Add examples for new functionality
- Keep documentation current
- Use clear, simple language

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- BBPTS version (`./bbpts -version`)
- Go version (`go version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Error messages and logs
- Configuration files (redact sensitive data)

### Feature Requests

For new features, please:

- Describe the problem you're trying to solve
- Explain why existing solutions don't work
- Provide examples of the desired functionality
- Consider implementation complexity

### Security Issues

- **DO NOT** report security vulnerabilities publicly
- Email security@bbpts.dev with details
- Allow time for fixes before public disclosure

## Recognition

Contributors are recognized in:
- GitHub repository contributors
- CHANGELOG.md for significant contributions
- Release notes
- Project documentation

Thank you for contributing to BBPTS! Your efforts help make security testing more effective and accessible.