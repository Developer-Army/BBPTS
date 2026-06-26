// Package ui — obsidian.go exports IDOR testing notes and other findings
// to Obsidian vault-compatible Markdown files.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// IDORNote represents a single IDOR testing note for Obsidian export.
type IDORNote struct {
	Target      string
	Pattern     string
	ParamName   string
	ParamType   string
	ObjectType  string
	Risk        string
	SampleIDs   []string
	SampleURLs  []string
	Checklist   string
}

// WriteIDORNotes writes IDOR testing checklists as individual Obsidian notes
// under the given vault directory. Each note is a standalone Markdown file
// with frontmatter-compatible metadata.
func WriteIDORNotes(vaultDir string, notes []IDORNote) error {
	if len(notes) == 0 {
		return nil
	}

	idorDir := filepath.Join(vaultDir, "BBPTS", "IDOR")
	if err := os.MkdirAll(idorDir, 0755); err != nil {
		return fmt.Errorf("create IDOR notes dir: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, note := range notes {
		slug := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			if r >= 'A' && r <= 'Z' {
				return r + 32
			}
			return '-'
		}, note.Pattern)
		slug = strings.Trim(slug, "-")
		if slug == "" {
			slug = "idor-target"
		}

		var b strings.Builder
		b.WriteString("---\n")
		b.WriteString(fmt.Sprintf("created: %s\n", now))
		b.WriteString(fmt.Sprintf("type: idor-testing\n"))
		b.WriteString(fmt.Sprintf("risk: %s\n", note.Risk))
		b.WriteString(fmt.Sprintf("object: %s\n", note.ObjectType))
		b.WriteString(fmt.Sprintf("param: %s (%s)\n", note.ParamName, note.ParamType))
		b.WriteString(fmt.Sprintf("target: %s\n", note.Target))
		b.WriteString("tags:\n")
		b.WriteString("  - bbpts\n")
		b.WriteString("  - idor\n")
		b.WriteString(fmt.Sprintf("  - %s\n", note.Risk))
		b.WriteString("---\n\n")

		b.WriteString(fmt.Sprintf("# IDOR Testing: %s\n\n", note.Pattern))
		b.WriteString(fmt.Sprintf("**Target:** `%s`\n", note.Target))
		b.WriteString(fmt.Sprintf("**Parameter:** `%s` (%s)\n", note.ParamName, note.ParamType))
		b.WriteString(fmt.Sprintf("**Object Type:** %s\n", note.ObjectType))
		b.WriteString(fmt.Sprintf("**Risk:** %s\n\n", strings.ToUpper(note.Risk)))

		if len(note.SampleIDs) > 0 {
			b.WriteString("## Sample IDs\n")
			for i, id := range note.SampleIDs {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("- ... and %d more\n", len(note.SampleIDs)-15))
					break
				}
				b.WriteString(fmt.Sprintf("- `%s`\n", id))
			}
			b.WriteString("\n")
		}

		if len(note.SampleURLs) > 0 {
			b.WriteString("## Sample URLs\n")
			for _, u := range note.SampleURLs {
				b.WriteString(fmt.Sprintf("- `%s`\n", u))
			}
			b.WriteString("\n")
		}

		if note.Checklist != "" {
			b.WriteString("## Testing Checklist\n\n")
			b.WriteString(note.Checklist)
			b.WriteString("\n")
		}

		filePath := filepath.Join(idorDir, slug+".md")
		if err := os.WriteFile(filePath, []byte(b.String()), 0644); err != nil {
			return fmt.Errorf("write IDOR note %s: %w", slug, err)
		}
	}

	return nil
}
