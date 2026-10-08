// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secretscan

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type Rule struct {
	Name    string
	Pattern *regexp.Regexp
}

type Finding struct {
	CommitID     string
	Path         string
	LineNumber   int
	RuleName     string
	SecretMasked string
}

var defaultRules = []Rule{
	{
		Name:    "Private Key",
		Pattern: regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----`),
	},
	{
		Name:    "AWS Access Key ID",
		Pattern: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
	},
	{
		Name:    "GitHub Personal Access Token",
		Pattern: regexp.MustCompile(`\b(gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b`),
	},
	{
		Name:    "GitLab Personal Access Token",
		Pattern: regexp.MustCompile(`\b(glpat-[a-zA-Z0-9_\-]{20,250})\b`),
	},
	{
		Name:    "Slack Token",
		Pattern: regexp.MustCompile(`\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b`),
	},
	{
		Name:    "Slack Webhook",
		Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`),
	},
	{
		Name:    "Google API Key",
		Pattern: regexp.MustCompile(`\b(AIza[0-9A-Za-z\\-_]{35})\b`),
	},
	{
		Name:    "Stripe API Key",
		Pattern: regexp.MustCompile(`\b([rs]k_(?:test|live)_[0-9a-zA-Z]{24,99})\b`),
	},
}

// MaskSecret masks sensitive characters while preserving identifiable prefixes and suffixes
func MaskSecret(secret string) string {
	if strings.HasPrefix(secret, "-----BEGIN") {
		return secret + " [REDACTED]"
	}
	n := len(secret)
	if n <= 8 {
		return "********"
	}
	prefixLen := 4
	suffixLen := 4
	if n < prefixLen+suffixLen {
		prefixLen = 2
		suffixLen = 2
	}
	return secret[:prefixLen] + strings.Repeat("*", n-prefixLen-suffixLen) + secret[n-suffixLen:]
}

// ScanPatch parses a git log patch diff and scans added lines for secrets
func ScanPatch(patchReader io.Reader) ([]Finding, error) {
	reader := bufio.NewReader(patchReader)
	var findings []Finding

	var currentCommit string
	var currentFile string
	currentLine := 0
	skipCurrentCommit := false
	inCommitMessage := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("ScanPatch: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")

		if strings.HasPrefix(line, "commit ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentCommit = parts[1]
			}
			skipCurrentCommit = false
			inCommitMessage = true
			currentFile = ""
			currentLine = 0
			continue
		}

		if inCommitMessage {
			if strings.HasPrefix(line, "diff --git ") {
				inCommitMessage = false
			} else {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "[skip-secret-scan]") || strings.Contains(lower, "[skip-push-protection]") {
					skipCurrentCommit = true
				}
				continue
			}
		}

		if strings.HasPrefix(line, "diff --git ") {
			currentFile = ""
			currentLine = 0
			continue
		}

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = line[6:]
			continue
		} else if strings.HasPrefix(line, "+++ ") {
			currentFile = ""
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			currentLine = parseHunkNewStart(line)
			continue
		}

		if skipCurrentCommit || currentFile == "" {
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:]
			if len(content) > 4096 {
				content = content[:4096]
			}

			for _, rule := range defaultRules {
				matches := rule.Pattern.FindAllString(content, -1)
				for _, match := range matches {
					findings = append(findings, Finding{
						CommitID:     currentCommit,
						Path:         currentFile,
						LineNumber:   currentLine,
						RuleName:     rule.Name,
						SecretMasked: MaskSecret(match),
					})
				}
			}
			currentLine++
		} else if strings.HasPrefix(line, " ") {
			currentLine++
		}
	}

	return findings, nil
}

func parseHunkNewStart(line string) int {
	_, sub, ok := strings.Cut(line, "+")
	if !ok {
		return 0
	}
	endIdx := strings.IndexAny(sub, ", @")
	if endIdx != -1 {
		sub = sub[:endIdx]
	}
	num, err := strconv.Atoi(sub)
	if err != nil {
		return 0
	}
	return num
}

// FormatFindings formats detected secrets into an actionable terminal error message
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("================================================================\n")
	sb.WriteString("Gitea Push Protection: Push rejected due to detected secret(s)\n")
	sb.WriteString("================================================================\n\n")
	sb.WriteString("The following secrets were detected in your push:\n\n")

	for _, f := range findings {
		fmt.Fprintf(&sb, "  - Rule:   %s\n", f.RuleName)
		if f.Path != "" {
			if f.LineNumber > 0 {
				fmt.Fprintf(&sb, "    File:   %s:%d\n", f.Path, f.LineNumber)
			} else {
				fmt.Fprintf(&sb, "    File:   %s\n", f.Path)
			}
		}
		if f.CommitID != "" {
			commitShort := f.CommitID
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}
			fmt.Fprintf(&sb, "    Commit: %s\n", commitShort)
		}
		fmt.Fprintf(&sb, "    Secret: %s\n\n", f.SecretMasked)
	}

	sb.WriteString("To resolve this rejection:\n")
	sb.WriteString("  1. Remove sensitive credentials from your commit history:\n")
	sb.WriteString("     git reset HEAD~1\n")
	sb.WriteString("  2. If this is intentional (e.g. test fixtures or mock data),\n")
	sb.WriteString("     bypass push protection with [skip-secret-scan] in the commit message:\n")
	sb.WriteString("     git commit --amend -m \"your message [skip-secret-scan]\"\n")
	sb.WriteString("================================================================")
	return sb.String()
}
