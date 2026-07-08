package engine

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type ThreatCorrelation struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	CVSS           float64 `json:"cvss"`
	EPSS           float64 `json:"epss"`
	MitreTactic    string  `json:"mitre_tactic"`
	MitreTechnique string  `json:"mitre_technique"`
	Description    string  `json:"description"`
}

type JsonCveEntry struct {
	ID              string   `json:"id"`
	Product         string   `json:"product"`
	Name            string   `json:"name"`
	CVSS            float64  `json:"cvss"`
	EPSS            float64  `json:"epss"`
	MitreTactic     string   `json:"mitre_tactic"`
	MitreTechnique  string   `json:"mitre_technique"`
	VersionKeywords []string `json:"version_keywords"`
	Description     string   `json:"description"`
}

// CorrelateThreats maps parsed ports, software versions, and native leaks to the threat matrix dynamically.
func CorrelateThreats(ports []BannerResult, leaks []LeakFinding) []ThreatCorrelation {
	correlations := []ThreatCorrelation{}
	database := loadLocalCveDatabase()

	// 1. Process ports & software versions using dynamic JSON registry
	for _, p := range ports {
		service := strings.ToLower(p.ServiceType)
		banner := strings.ToLower(p.RawBanner)

		for _, entry := range database {
			product := strings.ToLower(entry.Product)
			
			// Match product type and service keywords
			matchProduct := false
			if product == "openssh" && (service == "ssh" || strings.Contains(banner, "openssh")) {
				matchProduct = true
			} else if product == "nginx" && (service == "http" && strings.Contains(banner, "nginx")) {
				matchProduct = true
			} else if product == "apache" && (service == "http" && strings.Contains(banner, "apache")) {
				matchProduct = true
			} else if product == "tomcat" && (strings.Contains(banner, "tomcat") || strings.Contains(banner, "coyote")) {
				matchProduct = true
			} else if product == "iis" && (strings.Contains(banner, "microsoft-iis") || strings.Contains(banner, "iis/")) {
				matchProduct = true
			} else if product == "mysql" && (service == "mysql" || strings.Contains(banner, "mysql")) {
				matchProduct = true
			} else if product == "postgresql" && (service == "postgresql" || strings.Contains(banner, "postgresql") || strings.Contains(banner, "postgres")) {
				matchProduct = true
			} else if product == "php" && strings.Contains(banner, "php/") {
				matchProduct = true
			} else if product == "openssl" && strings.Contains(banner, "openssl") {
				matchProduct = true
			} else if product == "redis" && service == "redis" {
				matchProduct = true
			}

			if matchProduct {
				// Verify if the version keyword matches
				for _, versionKw := range entry.VersionKeywords {
					if strings.Contains(banner, strings.ToLower(versionKw)) {
						correlations = append(correlations, ThreatCorrelation{
							ID:             entry.ID,
							Name:           entry.Name,
							CVSS:           entry.CVSS,
							EPSS:           entry.EPSS,
							MitreTactic:    entry.MitreTactic,
							MitreTechnique: entry.MitreTechnique,
							Description:    entry.Description,
						})
						break // Matched this CVE entry for the port
					}
				}
			}
		}

		// Run remote lookup fallback to query Luxembourg CIRCL API
		productName, verString := extractProductAndVersion(p.ServiceType, p.RawBanner)
		if productName != "" && verString != "" {
			remoteCVEs := QueryRemoteCVEs(productName, verString)
			for _, rc := range remoteCVEs {
				// Avoid duplicates
				exists := false
				for _, existing := range correlations {
					if existing.ID == rc.ID {
						exists = true
						break
					}
				}
				if !exists {
					correlations = append(correlations, rc)
				}
			}
		}
	}

	// 2. Process native web leaks
	for _, l := range leaks {
		path := strings.ToLower(l.Path)
		for _, entry := range database {
			product := strings.ToLower(entry.Product)
			if product == "php" || product == "openssh" || product == "nginx" || product == "apache" || product == "tomcat" || product == "iis" || product == "mysql" || product == "postgresql" || product == "openssl" || product == "redis" {
				continue // Skip ports products in leaks iteration
			}

			matchedLeak := false
			if entry.ID == "VS-LEAK-ENV" && strings.Contains(path, ".env") {
				matchedLeak = true
			} else if entry.ID == "VS-LEAK-GIT" && strings.Contains(path, ".git") {
				matchedLeak = true
			} else if entry.ID == "VS-LEAK-SQL" && strings.Contains(path, ".sql") {
				matchedLeak = true
			} else if entry.ID == "VS-LEAK-ZIP" && (strings.Contains(path, ".zip") || strings.Contains(path, ".tar.gz")) {
				matchedLeak = true
			}

			if matchedLeak {
				correlations = append(correlations, ThreatCorrelation{
					ID:             entry.ID,
					Name:           entry.Name,
					CVSS:           entry.CVSS,
					EPSS:           entry.EPSS,
					MitreTactic:    entry.MitreTactic,
					MitreTechnique: entry.MitreTechnique,
					Description:    entry.Description,
				})
			}
		}
	}

	return correlations
}

func loadLocalCveDatabase() []JsonCveEntry {
	home, err := os.UserHomeDir()
	if err == nil {
		dbPath := filepath.Join(home, ".vulnsight", "cve_database.json")
		if _, err := os.Stat(dbPath); err == nil {
			data, err := ioutil.ReadFile(dbPath)
			if err == nil {
				var db []JsonCveEntry
				if json.Unmarshal(data, &db) == nil {
					return db
				}
			}
		}
	}

	// Dynamic hardcoded fallback database to prevent empty returns if JSON file is missing/corrupted
	return []JsonCveEntry{
		{
			ID:              "CVE-2020-15778",
			Product:         "openssh",
			Name:            "OpenSSH scp Command Injection",
			CVSS:            7.8,
			EPSS:            0.08,
			MitreTactic:     "Execution",
			MitreTechnique:  "T1059",
			VersionKeywords: []string{"8.2p1", "8.1", "8.0", "7.9"},
			Description:     "Command injection vulnerability in scp in OpenSSH allows remote attackers to execute arbitrary commands via crafted filenames.",
		},
		{
			ID:              "CVE-2021-41773",
			Product:         "apache",
			Name:            "Apache httpd Path Traversal & RCE",
			CVSS:            9.8,
			EPSS:            0.97,
			MitreTactic:     "Initial Access",
			MitreTechnique:  "T1190",
			VersionKeywords: []string{"2.4.49", "2.4.50"},
			Description:     "A path traversal and file disclosure vulnerability was found in Apache HTTP Server 2.4.49. An attacker could use path traversal to map and read files outside the document root.",
		},
		{
			ID:              "VS-LEAK-ENV",
			Product:         "leak",
			Name:            "Exposed Environment Credentials",
			CVSS:            9.5,
			EPSS:            0.85,
			MitreTactic:     "Credential Access",
			MitreTechnique:  "T1552",
			Description:     "Publicly accessible .env configuration file exposed on the web server leaking active database credentials and access keys.",
		},
	}
}

func extractProductAndVersion(service, banner string) (string, string) {
	bannerLower := strings.ToLower(banner)
	serviceLower := strings.ToLower(service)

	product := ""
	version := ""

	// Identify product
	if strings.Contains(bannerLower, "openssh") {
		product = "openssh"
	} else if strings.Contains(bannerLower, "nginx") {
		product = "nginx"
	} else if strings.Contains(bannerLower, "apache") {
		product = "apache"
	} else if strings.Contains(bannerLower, "tomcat") {
		product = "tomcat"
	} else if strings.Contains(bannerLower, "iis") || strings.Contains(bannerLower, "microsoft-iis") {
		product = "iis"
	} else if strings.Contains(bannerLower, "vsftpd") {
		product = "vsftpd"
	} else if strings.Contains(bannerLower, "mysql") {
		product = "mysql"
	} else if strings.Contains(bannerLower, "postgres") || strings.Contains(bannerLower, "postgresql") {
		product = "postgresql"
	} else if strings.Contains(bannerLower, "php/") {
		product = "php"
	} else if strings.Contains(bannerLower, "openssl") {
		product = "openssl"
	} else if serviceLower == "redis" || strings.Contains(bannerLower, "redis") {
		product = "redis"
	}

	if product == "" {
		if serviceLower != "" && serviceLower != "unknown" {
			product = serviceLower
		}
	}

	// Simple version extraction: look for digits separated by dots or letters like "8.2p1"
	words := strings.Fields(strings.ReplaceAll(banner, "/", " "))
	for _, word := range words {
		word = strings.Trim(word, "(),;")
		if hasDigitsAndDots(word) {
			version = word
			break
		}
	}

	return product, version
}

func hasDigitsAndDots(s string) bool {
	hasDigit := false
	hasDot := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		if r == '.' {
			hasDot = true
		}
	}
	return hasDigit && (hasDot || strings.Contains(s, "p") || strings.Contains(s, "rc"))
}
