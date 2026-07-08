package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"vulnsight.ai/internal/db"
	"vulnsight.ai/internal/engine"
	"vulnsight.ai/internal/setup"
	"fmt"
	"strconv"
	"regexp"
	"strings"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for now
}

type ActiveScan struct {
	mu        sync.RWMutex
	Target    string
	Events    []engine.ScanEvent
	Listeners map[string]chan engine.ScanEvent
	Done      bool
}

var (
	activeScans = make(map[string]*ActiveScan)
	activeMutex = sync.Mutex{}
)

// StartScanHandler initiates a scan
func StartScanHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target         string `json:"target"`
		Model          string `json:"model"`
		Ports          string `json:"ports"`
		Speed          string `json:"speed"`
		Depth          string `json:"depth"`
		CustomTemplate string `json:"custom_template"`
		Proxy          string `json:"proxy"`
		UserAgent      string `json:"user_agent"`
		RateLimit      int    `json:"rate_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !engine.ValidateTarget(req.Target) {
		http.Error(w, "Invalid target format", http.StatusBadRequest)
		return
	}

	model := req.Model
	if model == "" {
		model = "deepseek-coder:latest" // default fallback
	}

	// Generate a simple unique ID for the websocket stream
	scanID := req.Target + "-" + time.Now().Format("150405")

	eventChan := make(chan engine.ScanEvent, 100)
	
	active := &ActiveScan{
		Target:    req.Target,
		Events:    make([]engine.ScanEvent, 0),
		Listeners: make(map[string]chan engine.ScanEvent),
	}

	activeMutex.Lock()
	activeScans[scanID] = active
	activeMutex.Unlock()

	// Start engine in background goroutine
	go func() {
		config := engine.ScanConfig{
			Ports:          req.Ports,
			Speed:          req.Speed,
			Depth:          req.Depth,
			CustomTemplate: req.CustomTemplate,
			Proxy:          req.Proxy,
			UserAgent:      req.UserAgent,
			RateLimit:      req.RateLimit,
		}
		// Run scan in background
		go engine.RunFullScan(active.Target, model, config, eventChan)

		// Drain events to store in memory history and broadcast to active listeners
		for event := range eventChan {
			active.mu.Lock()
			active.Events = append(active.Events, event)
			for _, listener := range active.Listeners {
				select {
				case listener <- event:
				default:
					// Drop event to listener if they are lagging, avoiding blocking
				}
			}
			active.mu.Unlock()

			// Save to database when scan completes
			if event.Type == "done" {
				_, err := db.SaveScanResult(active.Target, event.Data)
				if err != nil {
					log.Printf("Error saving scan result for %s: %v", active.Target, err)
				}
				active.mu.Lock()
				active.Done = true
				active.mu.Unlock()
			}
		}

		// Keep scan data cached in memory for 10 minutes to allow user reconnects
		time.Sleep(10 * time.Minute)
		activeMutex.Lock()
		delete(activeScans, scanID)
		activeMutex.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID, "status": "started"})
}

// ScanWebSocketHandler streams results to the frontend
func ScanWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")

	activeMutex.Lock()
	active, exists := activeScans[scanID]
	activeMutex.Unlock()

	if !exists {
		http.Error(w, "Scan ID not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WS Upgrade error:", err)
		return
	}
	defer conn.Close()

	// Create listener for new events
	listenerChan := make(chan engine.ScanEvent, 100)
	listenerID := fmt.Sprintf("%d", time.Now().UnixNano())

	active.mu.Lock()
	// 1. Play back any missed history events
	for _, event := range active.Events {
		err := conn.WriteJSON(event)
		if err != nil {
			active.mu.Unlock()
			return
		}
	}
	// 2. Register listener for new updates if scan is still active
	if !active.Done {
		active.Listeners[listenerID] = listenerChan
	}
	active.mu.Unlock()

	defer func() {
		active.mu.Lock()
		delete(active.Listeners, listenerID)
		active.mu.Unlock()
		close(listenerChan)
	}()

	// 3. Stream real-time events as they occur
	if !active.Done {
		for event := range listenerChan {
			err := conn.WriteJSON(event)
			if err != nil {
				break
			}
			if event.Type == "done" {
				break
			}
		}
	}
}

// GetScansHandler returns history
func GetScansHandler(w http.ResponseWriter, r *http.Request) {
	scans, err := db.GetAllScans()
	if err != nil {
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

type NmapService struct {
	Port     string
	State    string
	Service  string
	Version  string
}

func parseNmapServices(nmapOutput string) []NmapService {
	var services []NmapService
	lines := strings.Split(nmapOutput, "\n")
	re := regexp.MustCompile(`^(\d+/\w+)\s+(\w+)\s+(\S+)\s*(.*)$`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			version := ""
			if len(matches) > 4 {
				version = strings.TrimSpace(matches[4])
			}
			services = append(services, NmapService{
				Port:     matches[1],
				State:    matches[2],
				Service:  matches[3],
				Version:  version,
			})
		}
	}
	return services
}

// GenerateReportHandler generates HTML report for a specific scan ID
func GenerateReportHandler(w http.ResponseWriter, r *http.Request) {
	scanIDStr := chi.URLParam(r, "id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		http.Error(w, "Invalid scan ID", http.StatusBadRequest)
		return
	}

	targetScan, err := db.GetScanByID(scanID)
	if err != nil {
		log.Printf("Error in GetScanByID for ID %d: %v", scanID, err)
		http.Error(w, "Scan not found or error loading scan data", http.StatusNotFound)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(targetScan.ScanData, &data); err != nil {
		log.Printf("Failed to unmarshal scan data for report ID %d: %v", scanID, err)
		data = map[string]interface{}{}
	}

	target := targetScan.Target
	timestamp := targetScan.Timestamp

	// Extract details
	nmapRaw, _ := data["nmap_scan"].(string)
	nmapServices := parseNmapServices(nmapRaw)

	subdomainsRaw, _ := data["subdomains"].([]interface{})
	var subdomains []string
	for _, s := range subdomainsRaw {
		if str, ok := s.(string); ok {
			subdomains = append(subdomains, str)
		}
	}

	technologiesRaw, _ := data["technologies"].([]interface{})
	findingsRaw, _ := data["nuclei_findings"].([]interface{})
	aiSuggestions, _ := data["ai_suggestions"].(string)

	kevAlertsRaw, _ := data["kev_alerts"].([]interface{})
	var kevAlertsHTML string
	if len(kevAlertsRaw) > 0 {
		kevAlertsHTML = `
		<div class="secure-card" style="border-left: 4px solid #ef4444; margin-bottom: 25px; background: #fff5f5; color: #991b1b; padding: 20px; border-radius: 12px;">
			<div class="icon" style="font-size: 28px; margin-right: 15px; float: left;">🚨</div>
			<div class="content" style="overflow: hidden;">
				<h3 style="margin: 0 0 10px 0; font-size: 16px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em;">CISA Active Exploit Advisory</h3>
				<p style="margin: 0 0 15px 0; font-size: 13px; opacity: 0.9;">The following threats are classified in the CISA KEV Catalog as <strong>actively exploited in the wild</strong> by threat groups. Immediate patching is mandatory.</p>
				<div>`
		for _, k := range kevAlertsRaw {
			if kMap, ok := k.(map[string]interface{}); ok {
				cveID, _ := kMap["cve_id"].(string)
				vulnName, _ := kMap["vulnerability_name"].(string)
				desc, _ := kMap["description"].(string)
				action, _ := kMap["required_action"].(string)

				kevAlertsHTML += fmt.Sprintf(`
				<div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 10px;">
					<strong style="font-size: 13px; color: #b91c1c;">%s: %s</strong>
					<p style="margin: 5px 0; font-size: 12px; color: #7f1d1d; opacity: 0.85;">%s</p>
					<div style="font-size: 11px; font-weight: bold; color: #b91c1c; margin-top: 5px;">Required Action: %s</div>
				</div>`, cveID, vulnName, desc, action)
			}
		}
		kevAlertsHTML += `
				</div>
			</div>
			<div style="clear: both;"></div>
		</div>`
	} else {
		kevAlertsHTML = ""
	}

	cveCorrelationsRaw, _ := data["cve_correlations"].([]interface{})
	var cveCorrelationsHTML string
	if len(cveCorrelationsRaw) > 0 {
		cveCorrelationsHTML = `
		<div class="section-card" style="border-left: 4px solid #8b5cf6;">
			<h2>📊 CVE & MITRE ATT&CK Threat Correlation</h2>
			<div style="margin-top: 15px;">`
		for _, c := range cveCorrelationsRaw {
			if cMap, ok := c.(map[string]interface{}); ok {
				cveID, _ := cMap["id"].(string)
				cveName, _ := cMap["name"].(string)
				cvss, _ := cMap["cvss"].(float64)
				epss, _ := cMap["epss"].(float64)
				tactic, _ := cMap["mitre_tactic"].(string)
				technique, _ := cMap["mitre_technique"].(string)
				desc, _ := cMap["description"].(string)

				cveCorrelationsHTML += fmt.Sprintf(`
				<div style="border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; margin-bottom: 12px; background: var(--bg-body);">
					<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
						<span style="font-weight: 800; font-size: 14px; color: var(--text-main);">%s: %s</span>
						<div style="display: flex; gap: 6px; align-items: center;">
							<span class="badge" style="background: #7c3aed; color: #fff; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;">MITRE %s</span>
							<span class="badge" style="background: #4b5563; color: #fff; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;">CVSS %.1f</span>
							<span class="badge" style="background: #374151; color: #fff; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;">EPSS %.0f%%</span>
						</div>
					</div>
					<p style="margin: 0 0 8px 0; font-size: 13px; color: var(--text-muted);">%s</p>
					<div style="font-size: 11px; font-weight: bold; color: #7c3aed;">
						Tactic Alignment: %s | Technique Code: %s
					</div>
				</div>`, cveID, cveName, technique, cvss, epss*100, desc, tactic, technique)
			}
		}
		cveCorrelationsHTML += `
			</div>
		</div>`
	} else {
		cveCorrelationsHTML = ""
	}

	nativeLeaksRaw, _ := data["native_leaks"].([]interface{})
	var nativeLeaksHTML string
	if len(nativeLeaksRaw) > 0 {
		nativeLeaksHTML = `
		<div class="section-card" style="border-left: 4px solid #f97316;">
			<h2>🔥 Proprietary VulnSightAI Web Leaks</h2>
			<div style="margin-top: 15px;">`
		for _, l := range nativeLeaksRaw {
			if lMap, ok := l.(map[string]interface{}); ok {
				path, _ := lMap["path"].(string)
				leakType, _ := lMap["type"].(string)
				severity, _ := lMap["severity"].(string)
				description, _ := lMap["description"].(string)
				evidence, _ := lMap["evidence"].(string)

				badgeClass := "badge-" + strings.ToLower(severity)
				nativeLeaksHTML += fmt.Sprintf(`
				<div style="border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; margin-bottom: 12px; background: var(--bg-body);">
					<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
						<span style="font-weight: 800; font-size: 14px; color: var(--text-main);">%s (<code>%s</code>)</span>
						<span class="badge %s">%s</span>
					</div>
					<p style="margin: 0 0 8px 0; font-size: 13px; color: var(--text-muted);">%s</p>
					<pre style="margin: 0; background: #000; color: #22c55e; padding: 10px; border-radius: 6px; font-size: 11px; font-family: monospace; overflow-x: auto; max-height: 120px;">%s</pre>
				</div>`, leakType, path, badgeClass, severity, description, evidence)
			}
		}
		nativeLeaksHTML += `
			</div>
		</div>`
	} else {
		nativeLeaksHTML = ""
	}

	wafName, _ := data["waf"].(string)
	wafDetail, _ := data["waf_details"].(string)
	var wafAlertHTML string
	if wafName != "" && wafName != "None" {
		wafAlertHTML = fmt.Sprintf(`
		<div class="secure-card" style="border-left: 4px solid #ef4444; margin-bottom: 25px; background: #fef2f2; color: #991b1b; padding: 20px; border-radius: 12px;">
			<div class="icon" style="font-size: 24px; margin-right: 15px; float: left;">🛡️</div>
			<div class="content" style="overflow: hidden;">
				<h3 style="margin: 0 0 5px 0; font-size: 16px; font-weight: 800;">Web Application Firewall (WAF) Detected</h3>
				<p style="margin: 0; font-size: 13px; opacity: 0.9;">Active protection <strong>%s</strong> was identified shielding this asset (%s). Scans were automatically auto-tuned for safety.</p>
			</div>
			<div style="clear: both;"></div>
		</div>`, wafName, wafDetail)
	} else {
		wafAlertHTML = ""
	}

	// Severity counts and overall risk metrics
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	riskLevel := "SECURE"
	riskColor := "#10b981" // Green

	for _, f := range findingsRaw {
		if fMap, ok := f.(map[string]interface{}); ok {
			if info, ok := fMap["info"].(map[string]interface{}); ok {
				sev, _ := info["severity"].(string)
				sev = strings.ToUpper(sev)
				switch sev {
				case "CRITICAL":
					critCount++
				case "HIGH":
					highCount++
				case "MEDIUM":
					medCount++
				case "LOW":
					lowCount++
				case "INFO":
					infoCount++
				}
			}
		}
	}

	for _, l := range nativeLeaksRaw {
		if lMap, ok := l.(map[string]interface{}); ok {
			sev, _ := lMap["severity"].(string)
			sev = strings.ToUpper(sev)
			switch sev {
			case "CRITICAL":
				critCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				medCount++
			case "LOW":
				lowCount++
			}
		}
	}

	for _, c := range cveCorrelationsRaw {
		if cMap, ok := c.(map[string]interface{}); ok {
			cvss, _ := cMap["cvss"].(float64)
			if cvss >= 9.0 {
				critCount++
			} else if cvss >= 7.0 {
				highCount++
			} else if cvss >= 4.0 {
				medCount++
			} else if cvss > 0.0 {
				lowCount++
			}
		}
	}

	totalVulns := critCount + highCount + medCount + lowCount + infoCount
	if critCount > 0 {
		riskLevel = "CRITICAL"
		riskColor = "#ef4444" // Bright Red
	} else if highCount > 0 {
		riskLevel = "HIGH"
		riskColor = "#f97316" // Orange
	} else if medCount > 0 {
		riskLevel = "MEDIUM"
		riskColor = "#eab308" // Yellow
	} else if lowCount > 0 {
		riskLevel = "LOW"
		riskColor = "#3b82f6" // Blue
	} else if infoCount > 0 {
		riskLevel = "INFO"
		riskColor = "#6b7280" // Gray
	}

	// Convert AI recommendations markdown to clean HTML list tags
	var aiHTML string
	if aiSuggestions == "" {
		aiHTML = "<p class='no-vulns'>No automated AI suggestions compiled for this operation.</p>"
	} else {
		// Basic markdown list block parser
		lines := strings.Split(aiSuggestions, "\n")
		var builder strings.Builder
		inList := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "###") {
				if inList {
					builder.WriteString("</ul>")
					inList = false
				}
				builder.WriteString(fmt.Sprintf("<h3>%s</h3>", strings.TrimPrefix(line, "###")))
			} else if strings.HasPrefix(line, "##") {
				if inList {
					builder.WriteString("</ul>")
					inList = false
				}
				builder.WriteString(fmt.Sprintf("<h2>%s</h2>", strings.TrimPrefix(line, "##")))
			} else if strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ") {
				if !inList {
					builder.WriteString("<ul class='bullet-list'>")
					inList = true
				}
				content := strings.TrimPrefix(strings.TrimPrefix(line, "* "), "- ")
				// Make bold formatting inside list items clean
				content = strings.ReplaceAll(content, "**", "<strong>")
				content = strings.ReplaceAll(content, "<strong>", "<strong>") // simple replacements
				builder.WriteString(fmt.Sprintf("<li>%s</li>", content))
			} else {
				if inList {
					builder.WriteString("</ul>")
					inList = false
				}
				builder.WriteString(fmt.Sprintf("<p>%s</p>", line))
			}
		}
		if inList {
			builder.WriteString("</ul>")
		}
		aiHTML = builder.String()
	}

	// Generate subdomains list
	var subdomainsHTML string
	if len(subdomains) == 0 {
		subdomainsHTML = "<p class='no-data'>No active subdomains discovered.</p>"
	} else {
		subdomainsHTML = "<div class='badge-container'>"
		for _, s := range subdomains {
			subdomainsHTML += fmt.Sprintf("<span class='tech-badge'>%s</span>", s)
		}
		subdomainsHTML += "</div>"
	}

	// Generate tech fingerprints list
	var techHTML string
	if len(technologiesRaw) == 0 {
		techHTML = "<p class='no-data'>No technology signatures identified.</p>"
	} else {
		techHTML = "<div class='badge-container'>"
		for _, t := range technologiesRaw {
			if tMap, ok := t.(map[string]interface{}); ok {
				name, _ := tMap["name"].(string)
				version, _ := tMap["version"].(string)
				badge := name
				if version != "" {
					badge += " v" + version
				}
				techHTML += fmt.Sprintf("<span class='tech-badge'>%s</span>", badge)
			} else if tStr, ok := t.(string); ok {
				techHTML += fmt.Sprintf("<span class='tech-badge'>%s</span>", tStr)
			}
		}
		techHTML += "</div>"
	}

	// Generate vulnerabilities index collapsible blocks
	var vulnsHTML string
	if len(findingsRaw) == 0 {
		vulnsHTML = `
		<div class='secure-card'>
			<div class='icon'>🛡️</div>
			<div class='content'>
				<h3>No Vulnerabilities Found</h3>
				<p>Our standard signature sets and Nuclei scans detected no high-risk active threats on this asset.</p>
			</div>
		</div>`
	} else {
		for _, f := range findingsRaw {
			if fMap, ok := f.(map[string]interface{}); ok {
				info, _ := fMap["info"].(map[string]interface{})
				name, _ := info["name"].(string)
				severity, _ := info["severity"].(string)
				description, _ := info["description"].(string)
				reference, _ := fMap["matched-at"].(string)

				badgeClass := "badge-" + strings.ToLower(severity)
				vulnsHTML += fmt.Sprintf(`
				<details class="vuln-card border-%s">
					<summary>
						<span class="badge %s">%s</span>
						<span class="vuln-title">%s</span>
						<span class="vuln-arrow">▼</span>
					</summary>
					<div class="vuln-details">
						<p><strong>Description:</strong> %s</p>
						<p><strong>Target URL:</strong> <a href="%s" target="_blank" class="accent-link">%s</a></p>
					</div>
				</details>`, strings.ToLower(severity), badgeClass, strings.ToUpper(severity), name, description, reference, reference)
			}
		}
	}

	// Generate Nmap services table rows
	var nmapTableHTML string
	if len(nmapServices) == 0 {
		nmapTableHTML = "<tr><td colspan='4' class='text-center text-muted'>No open ports detected or port scan was bypassed.</td></tr>"
	} else {
		for _, s := range nmapServices {
			nmapTableHTML += fmt.Sprintf(`
			<tr>
				<td><strong>%s</strong></td>
				<td><span class="state-indicator online">%s</span></td>
				<td>%s</td>
				<td class="text-muted font-mono">%s</td>
			</tr>`, s.Port, s.State, s.Service, s.Version)
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnSightAI Security Assessment Report - %s</title>
    <style>
        :root {
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --primary: #4f46e5;
            --primary-hover: #4338ca;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }

        header {
            background-color: #0f172a;
            color: #ffffff;
            padding: 30px 40px;
            border-bottom: 4px solid var(--primary);
            position: relative;
        }

        .header-content {
            max-w: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-branding h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .header-branding p {
            margin: 5px 0 0 0;
            color: #94a3b8;
            font-size: 13px;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 1px;
        }

        .classification-tag {
            background-color: #ef4444;
            color: white;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .container {
            max-w: 1200px;
            margin: 40px auto;
            padding: 0 20px;
            box-sizing: border-box;
        }

        .action-bar {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 25px;
        }

        .btn-print {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 700;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2);
            transition: all 0.2s;
        }

        .btn-print:hover {
            background-color: var(--primary-hover);
        }

        .grid-stats {
            display: grid;
            grid-template-cols: 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }

        @media(min-width: 768px) {
            .grid-stats {
                grid-template-cols: repeat(4, 1fr);
            }
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 800;
            margin: 0;
        }

        .posture-badge {
            display: inline-block;
            font-size: 18px;
            font-weight: 800;
            padding: 4px 12px;
            border-radius: 6px;
            text-align: center;
            width: fit-content;
        }

        .section-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 35px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }

        .section-card h2 {
            margin-top: 0;
            margin-bottom: 25px;
            font-size: 18px;
            font-weight: 800;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Vulnerabilities details cards styling */
        .vuln-card {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            background: var(--bg-body);
        }

        .vuln-card[open] {
            border-color: #cbd5e1;
        }

        .vuln-card summary {
            padding: 16px 20px;
            font-weight: 700;
            cursor: pointer;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 15px;
            outline: none;
        }

        .vuln-card summary::-webkit-details-marker {
            display: none;
        }

        .vuln-title {
            flex-grow: 1;
            font-size: 14px;
        }

        .vuln-arrow {
            font-size: 10px;
            color: var(--text-muted);
            transition: transform 0.2s;
        }

        .vuln-card[open] summary .vuln-arrow {
            transform: rotate(180deg);
        }

        .vuln-details {
            padding: 20px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-card);
            font-size: 14px;
        }

        .vuln-details p {
            margin: 0 0 10px 0;
        }

        .vuln-details p:last-child {
            margin-bottom: 0;
        }

        /* Badges */
        .badge {
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-critical { background: #fef2f2; color: #991b1b; border: 1px solid #fee2e2; }
        .badge-high { background: #fff7ed; color: #c2410c; border: 1px solid #ffedd5; }
        .badge-medium { background: #fef9c3; color: #a16207; border: 1px solid #fef08a; }
        .badge-low { background: #eff6ff; color: #1d4ed8; border: 1px solid #dbeafe; }
        .badge-info { background: #f3f4f6; color: #374151; border: 1px solid #e5e7eb; }

        .border-critical { border-left: 5px solid #ef4444; }
        .border-high { border-left: 5px solid #f97316; }
        .border-medium { border-left: 5px solid #eab308; }
        .border-low { border-left: 5px solid #3b82f6; }
        .border-info { border-left: 5px solid #6b7280; }

        /* Secure template card */
        .secure-card {
            display: flex;
            align-items: center;
            gap: 20px;
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 12px;
            padding: 20px;
        }

        .secure-card .icon {
            font-size: 32px;
        }

        .secure-card h3 {
            margin: 0;
            color: #166534;
            font-size: 16px;
        }

        .secure-card p {
            margin: 5px 0 0 0;
            color: #14532d;
            font-size: 13px;
        }

        /* Nmap Table */
        table {
            width: 100%%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th {
            text-align: left;
            padding: 12px 16px;
            border-bottom: 2px solid var(--border-color);
            color: var(--text-muted);
            font-weight: 700;
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
        }

        tr:last-child td {
            border-bottom: none;
        }

        .state-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }

        .state-indicator::before {
            content: "";
            width: 8px;
            height: 8px;
            border-radius: 50%%;
        }

        .state-indicator.online { color: #166534; }
        .state-indicator.online::before { background-color: #22c55e; }

        .font-mono {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        .text-muted {
            color: var(--text-muted);
        }

        .text-center {
            text-align: center;
        }

        /* Tech badges container */
        .badge-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .tech-badge {
            background-color: var(--bg-body);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            font-family: ui-monospace, SFMono-Regular, monospace;
        }

        .bullet-list {
            padding-left: 20px;
            margin: 10px 0;
        }

        .bullet-list li {
            margin-bottom: 8px;
            font-size: 14px;
        }

        .accent-link {
            color: var(--primary);
            text-decoration: none;
        }

        .accent-link:hover {
            text-decoration: underline;
        }

        /* PDF Printing Customizations */
        @media print {
            body {
                background-color: white;
                font-size: 12px;
            }

            .container {
                max-width: 100%%;
                margin: 0;
                padding: 0;
            }

            .action-bar {
                display: none;
            }

            .section-card {
                box-shadow: none;
                border: 1px solid #cbd5e1;
                page-break-inside: avoid;
                margin-bottom: 20px;
                padding: 20px;
            }

            .vuln-card {
                page-break-inside: avoid;
            }

            .vuln-details {
                display: block !important;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <div class="header-branding">
                <h1>🛡️ VULNSIGHTAI REPORT</h1>
                <p>Security Vulnerability Assessment Telemetry</p>
            </div>
            <div class="classification-tag">CONFIDENTIAL</div>
        </div>
    </header>

    <div class="container">
        <!-- Action Bar -->
        <div class="action-bar">
            <button onclick="window.print()" class="btn-print">
                <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M2.5 8a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1z"/>
                    <path d="M5 1a2 2 0 0 0-2 2v2H2a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2H5zM4 3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2H4V3zm1 5a2 2 0 0 0-2 2v1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v-1a2 2 0 0 0-2-2H5zm7 2v3a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1z"/>
                </svg>
                Save as PDF
            </button>
        </div>

        <!-- CISA KEV Active Exploit Alert -->
        %s

        <!-- WAF Detection Alert -->
        %s

        <!-- Dashboard Stats Grid -->
        <div class="grid-stats">
            <div class="stat-card">
                <span class="stat-label">Security Posture</span>
                <span class="posture-badge" style="background-color: %s20; color: %s">%s</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Target Asset</span>
                <span class="stat-value" style="font-size: 15px; font-family: monospace; word-break: break-all;">%s</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Scan Timestamp</span>
                <span class="stat-value" style="font-size: 14px;">%s</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Vulnerabilities Detected</span>
                <span class="stat-value" style="color: %s">%d</span>
            </div>
        </div>

        <!-- AI Mitigation Suggestions -->
        <div class="section-card">
            <h2>🤖 AI Security Assessment & Recommendations</h2>
            <div class="ai-content">
                %s
            </div>
        </div>

        <!-- Proprietary Web Leak Detections -->
        %s

        <!-- CVE & MITRE ATT&CK Threat Correlation Matrix -->
        %s

        <!-- Vulnerabilities List -->
        <div class="section-card">
            <h2>🔍 Threat & Vulnerability Index</h2>
            %s
        </div>

        <!-- Nmap Port Scan -->
        <div class="section-card">
            <h2>🔌 Network Port Footprint</h2>
            <table style="margin-top: 15px;">
                <thead>
                    <tr>
                        <th>Port / Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Software Version</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
        </div>

        <!-- Subdomains -->
        <div class="section-card">
            <h2>🌐 Identified Subdomain Namespace</h2>
            %s
        </div>

        <!-- Technology Badges -->
        <div class="section-card">
            <h2>💻 Technology & Framework Profiling</h2>
            %s
        </div>
    </div>
</body>
</html>`, target, kevAlertsHTML, wafAlertHTML, riskColor, riskColor, riskLevel, target, timestamp, riskColor, totalVulns, aiHTML, nativeLeaksHTML, cveCorrelationsHTML, vulnsHTML, nmapTableHTML, subdomainsHTML, techHTML)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"vulnsight_report_%s.html\"", targetScan.Target))
	w.Write([]byte(html))
}

type OllamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// GetModelsHandler queries dynamic models from Ollama
func GetModelsHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
		return
	}
	defer resp.Body.Close()

	var tags OllamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
		return
	}

	models := []string{}
	for _, m := range tags.Models {
		models = append(models, m.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

// GetDiagnosticsHandler runs a diagnostic health check on all required binaries
func GetDiagnosticsHandler(w http.ResponseWriter, r *http.Request) {
	diag := map[string]bool{
		"nmap":      checkToolInstalled("nmap"),
		"nuclei":    checkToolInstalled("nuclei"),
		"subfinder": checkToolInstalled("subfinder"),
		"katana":    checkToolInstalled("katana"),
		"whatweb":   checkToolInstalled("whatweb"),
		"ollama":    checkToolInstalled("ollama") || checkOllamaOnline(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diag)
}

// DebugDBHandler prints the raw database rows to help diagnose query issues
func DebugDBHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query("SELECT id, target, timestamp, length(scan_data) FROM scans")
	if err != nil {
		log.Printf("DebugDB error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type RowDebug struct {
		ID        int    `json:"id"`
		Target    string `json:"target"`
		Timestamp string `json:"timestamp"`
		Length    int    `json:"length"`
	}

	var list []RowDebug
	for rows.Next() {
		var rd RowDebug
		if err := rows.Scan(&rd.ID, &rd.Target, &rd.Timestamp, &rd.Length); err != nil {
			log.Printf("DebugDB scan error: %v", err)
			continue
		}
		list = append(list, rd)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func checkToolInstalled(name string) bool {
	return setup.IsToolInstalled(name)
}

// SetupToolsHandler runs bootstrap for subfinder and nuclei
func SetupToolsHandler(w http.ResponseWriter, r *http.Request) {
	type ToolStatus struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}

	results := map[string]ToolStatus{}

	// Bootstrap Subfinder (v2.6.6)
	err := setup.BootstrapTool("subfinder", "2.6.6")
	if err != nil {
		results["subfinder"] = ToolStatus{Status: "failed", Error: err.Error()}
	} else {
		results["subfinder"] = ToolStatus{Status: "installed"}
	}

	// Bootstrap Nuclei (v3.2.9)
	err = setup.BootstrapTool("nuclei", "3.2.9")
	if err != nil {
		results["nuclei"] = ToolStatus{Status: "failed", Error: err.Error()}
	} else {
		results["nuclei"] = ToolStatus{Status: "installed"}
	}

	// Bootstrap Katana (v1.1.1)
	err = setup.BootstrapTool("katana", "1.1.1")
	if err != nil {
		results["katana"] = ToolStatus{Status: "failed", Error: err.Error()}
	} else {
		results["katana"] = ToolStatus{Status: "installed"}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// GetScanByIDHandler returns scan details in raw JSON
func GetScanByIDHandler(w http.ResponseWriter, r *http.Request) {
	scanIDStr := chi.URLParam(r, "id")
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		http.Error(w, "Invalid scan ID", http.StatusBadRequest)
		return
	}

	targetScan, err := db.GetScanByID(scanID)
	if err != nil {
		log.Printf("Error in GetScanByID for ID %d: %v", scanID, err)
		http.Error(w, "Scan not found or error loading scan data", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(targetScan.ScanData)
}

func checkOllamaOnline() bool {
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get("http://localhost:11434/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

type TemplateMetadata struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

// ValidateTemplateHandler validates custom Nuclei template YAML structure
func ValidateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(req.YAML), &parsed); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Invalid YAML syntax: " + err.Error(),
		})
		return
	}

	// Verify Nuclei template structural requirements
	id, _ := parsed["id"].(string)
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Required field 'id' is missing or not a string",
		})
		return
	}

	info, ok := parsed["info"].(map[string]interface{})
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Required object 'info' is missing or invalid",
		})
		return
	}

	name, _ := info["name"].(string)
	severity, _ := info["severity"].(string)
	if name == "" || severity == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "Required fields 'info.name' and 'info.severity' must be non-empty strings",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
	})
}

// SaveTemplateHandler validates and saves custom Nuclei template to home directory
func SaveTemplateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate before saving
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(req.YAML), &parsed); err != nil {
		http.Error(w, "Invalid YAML syntax: "+err.Error(), http.StatusBadRequest)
		return
	}
	id, _ := parsed["id"].(string)
	if id == "" {
		http.Error(w, "Required template field 'id' is missing", http.StatusBadRequest)
		return
	}

	// Clean name and force yaml extension
	cleanName := filepath.Base(req.Name)
	if cleanName == "" || cleanName == "." || cleanName == "/" {
		cleanName = id
	}
	if !strings.HasSuffix(cleanName, ".yaml") && !strings.HasSuffix(cleanName, ".yml") {
		cleanName += ".yaml"
	}

	// Resolve templates path: ~/.vulnsight/custom-templates/
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, "Unable to resolve home space: "+err.Error(), http.StatusInternalServerError)
		return
	}
	templatesDir := filepath.Join(home, ".vulnsight", "custom-templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		http.Error(w, "Failed to initialize custom template path: "+err.Error(), http.StatusInternalServerError)
		return
	}

	targetPath := filepath.Join(templatesDir, cleanName)
	if err := os.WriteFile(targetPath, []byte(req.YAML), 0644); err != nil {
		http.Error(w, "Failed to save template file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "saved",
		"name":   cleanName,
		"path":   targetPath,
	})
}

// ListTemplatesHandler lists all custom Nuclei templates
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, "Unable to resolve home space: "+err.Error(), http.StatusInternalServerError)
		return
	}
	templatesDir := filepath.Join(home, ".vulnsight", "custom-templates")
	
	// Create folder if not exists
	os.MkdirAll(templatesDir, 0755)

	files, err := os.ReadDir(templatesDir)
	if err != nil {
		http.Error(w, "Failed to read template directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var templates []TemplateMetadata
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		ext := filepath.Ext(f.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(templatesDir, f.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var parsed map[string]interface{}
		if err := yaml.Unmarshal(content, &parsed); err != nil {
			continue
		}

		id, _ := parsed["id"].(string)
		title := id
		severity := "info"

		if info, ok := parsed["info"].(map[string]interface{}); ok {
			if name, ok := info["name"].(string); ok {
				title = name
			}
			if sev, ok := info["severity"].(string); ok {
				severity = sev
			}
		}

		templates = append(templates, TemplateMetadata{
			Name:     f.Name(),
			ID:       id,
			Title:    title,
			Severity: severity,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// ResetHandler completely removes all cached binaries and custom templates under ~/.vulnsight
func ResetHandler(w http.ResponseWriter, r *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dir := filepath.Join(home, ".vulnsight")
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("Reset error deleting folder: %v", err)
		http.Error(w, fmt.Sprintf("Failed to delete directory: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Recreate folder structure empty
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0755); err != nil {
		http.Error(w, "Failed to rebuild folder workspace structure", http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(filepath.Join(dir, "custom-templates"), 0755); err != nil {
		http.Error(w, "Failed to rebuild templates workspace structure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"reset_successful"}`))
}

