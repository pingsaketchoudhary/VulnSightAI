package engine

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type KEVAlert struct {
	CVEID          string `json:"cve_id"`
	Vulnerability  string `json:"vulnerability_name"`
	Description    string `json:"description"`
	RequiredAction string `json:"required_action"`
	DateAdded      string `json:"date_added"`
}

type CisaKevCatalog struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID          string `json:"cveID"`
		Vulnerability  string `json:"vulnerabilityName"`
		Description    string `json:"shortDescription"`
		RequiredAction string `json:"requiredAction"`
		DateAdded      string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// MatchKEV checks if any correlated CVEs are inside the CISA Known Exploited Vulnerabilities catalog.
func MatchKEV(correlations []ThreatCorrelation) []KEVAlert {
	alerts := []KEVAlert{}
	catalog := loadKevCatalog()

	for _, c := range correlations {
		cveID := strings.ToUpper(c.ID)
		if !strings.HasPrefix(cveID, "CVE-") {
			continue // Skip custom internal leak codes (VS-LEAK-xxx)
		}

		matched := false
		if catalog != nil {
			for _, v := range catalog.Vulnerabilities {
				if strings.ToUpper(v.CVEID) == cveID {
					alerts = append(alerts, KEVAlert{
						CVEID:          v.CVEID,
						Vulnerability:  v.Vulnerability,
						Description:    v.Description,
						RequiredAction: v.RequiredAction,
						DateAdded:      v.DateAdded,
					})
					matched = true
					break
				}
			}
		}

		// Offline fallback registry for critical KEV zero-days in case download is skipped/offline
		if !matched {
			fallbackKEV := map[string]struct {
				VulnName string
				Desc     string
				Action   string
			}{
				"CVE-2021-41773": {
					VulnName: "Apache HTTP Server Path Traversal and RCE",
					Desc:     "Apache HTTP Server version 2.4.49 contains a path traversal vulnerability that is actively exploited in the wild to read arbitrary files and execute code.",
					Action:   "Upgrade Apache HTTP Server to version 2.4.51 or later.",
				},
				"CVE-2011-2523": {
					VulnName: "vsftpd Backdoor Command Execution",
					Desc:     "vsftpd version 2.3.4 contains an inserted backdoor triggered by a smiley face username, which is actively used in legacy vulnerability scans.",
					Action:   "Remove vsftpd 2.3.4 or patch/rebuild from trusted source repos.",
				},
				"CVE-2022-0543": {
					VulnName: "Redis Lua Sandbox Escape Vulnerability",
					Desc:     "Redis contains a Lua scripting sandbox escape vulnerability that is actively exploited by malware and botnets to execute RCE payloads.",
					Action:   "Apply security patches or upgrade Redis to patched release series.",
				},
				"CVE-2018-15473": {
					VulnName: "OpenSSH Username Enumeration",
					Desc:     "OpenSSH is prone to username enumeration. While low severity, threat actors use this widely to map active accounts.",
					Action:   "Upgrade OpenSSH or restrict password authentication attempts.",
				},
			}

			if item, exists := fallbackKEV[cveID]; exists {
				alerts = append(alerts, KEVAlert{
					CVEID:          cveID,
					Vulnerability:  item.VulnName,
					Description:    item.Desc,
					RequiredAction: item.Action,
					DateAdded:      "Embedded Fallback",
				})
			}
		}
	}

	return alerts
}

func loadKevCatalog() *CisaKevCatalog {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	cacheDir := filepath.Join(home, ".vulnsight")
	os.MkdirAll(cacheDir, 0755)
	cachePath := filepath.Join(cacheDir, "kev_catalog.json")

	// Try reading local cache file
	if _, err := os.Stat(cachePath); err == nil {
		// If file exists, read it
		data, err := ioutil.ReadFile(cachePath)
		if err == nil {
			var catalog CisaKevCatalog
			if json.Unmarshal(data, &catalog) == nil {
				return &catalog
			}
		}
	}

	// Proactively fetch online catalog if missing and store it locally
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			var catalog CisaKevCatalog
			if json.Unmarshal(body, &catalog) == nil {
				// Cache file locally
				ioutil.WriteFile(cachePath, body, 0644)
				return &catalog
			}
		}
	}

	return nil
}
