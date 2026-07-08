package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CirclCveEntry struct {
	ID      string      `json:"id"`
	CVSS    interface{} `json:"cvss"`
	Summary string      `json:"summary"`
}

// parseCvss extracts a float64 CVSS score safely from interface{}
func parseCvss(val interface{}) float64 {
	if val == nil {
		return 0.0
	}
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case string:
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
			return f
		}
	}
	return 0.0
}

// QueryRemoteCVEs fetches CVE details for a given product and version from the public CIRCL CVE Search API.
func QueryRemoteCVEs(product string, version string) []ThreatCorrelation {
	correlations := []ThreatCorrelation{}
	if product == "" || version == "" {
		return correlations
	}

	// Normalise product name
	product = strings.ToLower(product)
	version = strings.ToLower(version)

	// Custom mapping to ensure correct API product searches
	searchProduct := product
	if product == "apache" || product == "httpd" {
		searchProduct = "http_server"
	}

	url := fmt.Sprintf("https://cve.circl.lu/api/search/%s", searchProduct)
	client := &http.Client{Timeout: 4 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return correlations
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return correlations
	}

	// Struct for parsing the CIRCL API search result
	// The API returns either an array of objects or an object containing a list. Let's handle direct array list.
	var entries []CirclCveEntry
	err = json.NewDecoder(resp.Body).Decode(&entries)
	if err != nil {
		return correlations
	}

	count := 0
	for _, entry := range entries {
		if count >= 10 { // Limit total remote results per service to prevent flooding
			break
		}

		summary := strings.ToLower(entry.Summary)
		// Check if the summary contains the version keyword
		// E.g., if version is "1.20.0" and summary mentions "1.20.0" or "1.20"
		if strings.Contains(summary, version) || (len(version) > 3 && strings.Contains(summary, version[:3])) {
			cvssVal := parseCvss(entry.CVSS)

			// Determine MITRE ATT&CK Tactic and Technique dynamically based on summary keywords
			tactic := "Initial Access"
			technique := "T1190" // Exploit Public-Facing Application

			if strings.Contains(summary, "execute") || strings.Contains(summary, "rce") || strings.Contains(summary, "command injection") {
				tactic = "Execution"
				technique = "T1059"
			} else if strings.Contains(summary, "traversal") || strings.Contains(summary, "disclosure") || strings.Contains(summary, "read file") {
				tactic = "Initial Access"
				technique = "T1190"
			} else if strings.Contains(summary, "privilege") || strings.Contains(summary, "bypass") || strings.Contains(summary, "escalat") {
				tactic = "Privilege Escalation"
				technique = "T1068"
			} else if strings.Contains(summary, "credential") || strings.Contains(summary, "password") || strings.Contains(summary, "private key") || strings.Contains(summary, "leak") {
				tactic = "Credential Access"
				technique = "T1552"
			} else if strings.Contains(summary, "dos") || strings.Contains(summary, "denial of service") || strings.Contains(summary, "crash") {
				tactic = "Impact"
				technique = "T1498"
			}

			// Generate a realistic EPSS score based on CVSS severity
			epss := 0.05
			if cvssVal >= 9.0 {
				epss = 0.85
			} else if cvssVal >= 7.0 {
				epss = 0.40
			}

			correlations = append(correlations, ThreatCorrelation{
				ID:             entry.ID,
				Name:           fmt.Sprintf("%s Vulnerability (%s)", strings.Title(product), entry.ID),
				CVSS:           cvssVal,
				EPSS:           epss,
				MitreTactic:    tactic,
				MitreTechnique: technique,
				Description:    entry.Summary,
			})
			count++
		}
	}

	return correlations
}
