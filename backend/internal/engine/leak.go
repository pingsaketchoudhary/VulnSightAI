package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type LeakFinding struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// ScanWebLeaks checks for common critical configuration exposures natively.
func ScanWebLeaks(baseURL string, eventChan chan<- ScanEvent) []LeakFinding {
	findings := []LeakFinding{}
	
	targets := []struct {
		Path        string
		Type        string
		Severity    string
		Description string
		Validators  []string // List of substrings that MUST be present to verify finding
	}{
		{
			Path:        "/.env",
			Type:        "Environment Secrets Disclosure",
			Severity:    "CRITICAL",
			Description: "Exposed environment configuration file containing database credentials, secrets, or API keys.",
			Validators:  []string{"DB_HOST", "DB_PASSWORD", "AWS_ACCESS_KEY", "SECRET_KEY", "JWT_SECRET", "APP_ENV"},
		},
		{
			Path:        "/.git/config",
			Type:        "Git Metadata Exposure",
			Severity:    "HIGH",
			Description: "Exposed Git repository configuration metadata, allowing source control cloning or repository map leak.",
			Validators:  []string{"[core]", "repositoryformatversion", "[remote", "[branch"},
		},
		{
			Path:        "/db.sql",
			Type:        "Database SQL Backup Disclosure",
			Severity:    "HIGH",
			Description: "Raw database dump file exposed publicly on the web root containing schema structures and raw tables data.",
			Validators:  []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE", "SELECT "},
		},
		{
			Path:        "/backup.sql",
			Type:        "Database SQL Backup Disclosure",
			Severity:    "HIGH",
			Description: "Raw database backup file exposed publicly on the web root containing schema structures and raw tables data.",
			Validators:  []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE", "SELECT "},
		},
		{
			Path:        "/.htaccess",
			Type:        "Server Configuration Disclosure",
			Severity:    "MEDIUM",
			Description: "Apache configuration file exposed, leaking server directories protection rules or internal route redirects.",
			Validators:  []string{"RewriteEngine", "AuthType", "RewriteCond", "Require all"},
		},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects to prevent wildcard redirections false positives
		},
	}

	for _, t := range targets {
		url := strings.TrimSuffix(baseURL, "/") + t.Path
		
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		if resp.StatusCode == http.StatusOK {
			// Read first 4KB to verify signatures and avoid false positives
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			cancel()

			if err == nil {
				bodyStr := string(bodyBytes)
				verified := false
				
				// Run validator matches
				for _, val := range t.Validators {
					if strings.Contains(bodyStr, val) {
						verified = true
						break
					}
				}

				if verified {
					// Extract a small preview of the finding
					lines := strings.Split(bodyStr, "\n")
					evidence := ""
					for i, line := range lines {
						if i > 5 { // Limit preview to 5 lines
							break
						}
						// Strip out sensitive secret keys in logs display
						if strings.Contains(line, "PASSWORD") || strings.Contains(line, "SECRET") || strings.Contains(line, "KEY") {
							parts := strings.SplitN(line, "=", 2)
							if len(parts) == 2 {
								line = parts[0] + "= [REDACTED_BY_VULNSIGHT]"
							}
						}
						evidence += line + "\n"
					}

					finding := LeakFinding{
						Path:        t.Path,
						Type:        t.Type,
						Severity:    t.Severity,
						Description: t.Description,
						Evidence:    strings.TrimSpace(evidence),
					}
					findings = append(findings, finding)
					
					// Stream notification event
					eventChan <- ScanEvent{
						Type:    "leak",
						Data:    finding,
						Message: fmt.Sprintf("[🔥 NATIVE LEAK DETECTED] %s exposed on %s", t.Type, url),
					}
				}
			}
		} else {
			resp.Body.Close()
			cancel()
		}
	}

	// 4. Binary backups checker (e.g. backup.zip, project.zip)
	binaryBackups := []string{"/backup.zip", "/backup.tar.gz", "/project.zip"}
	for _, path := range binaryBackups {
		url := strings.TrimSuffix(baseURL, "/") + path
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		if resp.StatusCode == http.StatusOK {
			// Read first 128 bytes to check magic headers or absence of HTML layout
			magicBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128))
			resp.Body.Close()
			cancel()

			if err == nil && len(magicBytes) > 0 {
				magicStr := string(magicBytes)
				isHTML := strings.Contains(strings.ToLower(magicStr), "<html") || strings.Contains(strings.ToLower(magicStr), "<!doctype")
				
				// Verify if it has ZIP magic signature or simply is NOT HTML (custom 404 wildcard router evasion)
				isZip := len(magicBytes) >= 4 && magicBytes[0] == 'P' && magicBytes[1] == 'K'
				isTarGz := len(magicBytes) >= 2 && magicBytes[0] == 0x1f && magicBytes[1] == 0x8b
				
				if (isZip || isTarGz || !isHTML) && resp.ContentLength != 0 {
					finding := LeakFinding{
						Path:        path,
						Type:        "Exposed Compressed Backup",
						Severity:    "HIGH",
						Description: "A compressed archive backup containing source files or application dumps was found exposed on the web server.",
						Evidence:    fmt.Sprintf("Content Length: %d bytes, Binary Magic Verified", resp.ContentLength),
					}
					findings = append(findings, finding)
					
					eventChan <- ScanEvent{
						Type:    "leak",
						Data:    finding,
						Message: fmt.Sprintf("[🔥 NATIVE LEAK DETECTED] Exposed Compressed Backup found on %s", url),
					}
				}
			}
		} else {
			resp.Body.Close()
			cancel()
		}
	}

	return findings
}
