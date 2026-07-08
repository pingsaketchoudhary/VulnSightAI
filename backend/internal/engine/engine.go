package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"path/filepath"

	"vulnsight.ai/internal/agents"
	"vulnsight.ai/internal/setup"
)

// ValidateTarget ensures target is a strictly valid domain or IP to prevent Command Injection.
func ValidateTarget(target string) bool {
	matched, _ := regexp.MatchString(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^[0-9]{1,3}(\.[0-9]{1,3}){3}$`, target)
	return matched
}

// ScanEvent represents a streamed event to the WebSocket
type ScanEvent struct {
	Type    string      `json:"type"`    // "info", "subdomain", "nuclei", "nmap", "technology", "done", "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ScanConfig struct {
	Ports          string `json:"ports"`
	Speed          string `json:"speed"`
	Depth          string `json:"depth"`
	CustomTemplate string `json:"custom_template"`
	Proxy          string `json:"proxy"`
	UserAgent      string `json:"user_agent"`
	RateLimit      int    `json:"rate_limit"`
}

func RunFullScan(target string, aiModel string, config ScanConfig, eventChan chan<- ScanEvent) {
	defer close(eventChan)

	if !ValidateTarget(target) {
		eventChan <- ScanEvent{Type: "error", Message: "Invalid target format. Potential injection detected."}
		return
	}

	eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Starting scan on %s with config: Ports=%s, Speed=%s, Depth=%s, Template=%s, Proxy=%s, UserAgent=%s, RateLimit=%d", target, config.Ports, config.Speed, config.Depth, config.CustomTemplate, config.Proxy, config.UserAgent, config.RateLimit)}
	
	// Data accumulator
	fullData := map[string]interface{}{
		"target": target,
	}

	// 0. WAF/CDN Fingerprinting
	eventChan <- ScanEvent{Type: "info", Message: "Analyzing target WAF/CDN protection..."}
	wafName, wafDetail := DetectWAF(target)
	if wafName != "" {
		eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("[🔥 WAF DETECTED] Target uses %s protection (%s).", wafName, wafDetail)}
		fullData["waf"] = wafName
		fullData["waf_details"] = wafDetail

		// Auto-tune parameters if not customized to avoid blockages
		if config.Speed == "T3" || config.Speed == "" {
			config.Speed = "T2" // Slow down to Sneaky mode
			eventChan <- ScanEvent{Type: "info", Message: "Auto-Tuning: Reducing scan speed to T2 (Stealth) to bypass WAF limitations."}
		}
		if config.RateLimit == 0 {
			config.RateLimit = 10 // Apply limit of 10 requests per second
			eventChan <- ScanEvent{Type: "info", Message: "Auto-Tuning: Applying request rate limit of 10 RPS to prevent origin rate limits."}
		}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "No active WAF/CDN protection detected. Running standard profiles."}
		fullData["waf"] = "None"
	}

	// 1. Subfinder
	var subdomains []string
	subfinderPath, err := setup.ResolveToolPath("subfinder")
	if err != nil {
		eventChan <- ScanEvent{Type: "info", Message: "Subfinder not installed. Skipping subdomain enumeration."}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "Running Subfinder..."}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		
		subfinderArgs := []string{"-d", target, "-silent"}
		if config.Depth == "deep" {
			subfinderArgs = append(subfinderArgs, "-all")
		}
		if config.Proxy != "" {
			subfinderArgs = append(subfinderArgs, "-proxy", config.Proxy)
		}
		if config.RateLimit > 0 {
			// Subfinder supports rate limit (maximum requests per second)
			subfinderArgs = append(subfinderArgs, "-rl", fmt.Sprintf("%d", config.RateLimit))
		}
		
		cmd := exec.CommandContext(ctx, subfinderPath, subfinderArgs...)
		out, err := cmd.Output()
		cancel()
		
		if err != nil {
			eventChan <- ScanEvent{Type: "error", Message: fmt.Sprintf("Subfinder error: %v", err)}
		} else {
			lines := strings.Split(string(out), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					subdomains = append(subdomains, l)
					eventChan <- ScanEvent{Type: "subdomain", Data: l}
				}
			}
		}
	}
	fullData["subdomains"] = subdomains

	// 2. Nmap
	nmapPath, err := setup.ResolveToolPath("nmap")
	if err != nil {
		eventChan <- ScanEvent{Type: "info", Message: "Nmap not installed. Skipping port scan."}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "Running Nmap Scan..."}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		
		nmapArgs := []string{}
		
		// Map speed
		if config.Speed != "" {
			nmapArgs = append(nmapArgs, "-"+config.Speed)
		} else {
			nmapArgs = append(nmapArgs, "-T3") // default
		}
		
		// Map ports
		if config.Ports == "all" {
			nmapArgs = append(nmapArgs, "-p-")
		} else if config.Ports != "" && config.Ports != "common" {
			// Validate custom port lists (numbers and commas only)
			portMatch, _ := regexp.MatchString(`^[0-9,]+$`, config.Ports)
			if portMatch {
				nmapArgs = append(nmapArgs, "-p", config.Ports)
			} else {
				nmapArgs = append(nmapArgs, "-F")
			}
		} else {
			nmapArgs = append(nmapArgs, "-F") // fast common ports default
		}
		
		// Map proxy and custom user agent details if specified
		if config.Proxy != "" {
			nmapArgs = append(nmapArgs, "--proxies", config.Proxy)
		}
		
		nmapArgs = append(nmapArgs, "-sV", target)
		cmd := exec.CommandContext(ctx, nmapPath, nmapArgs...)
		out, err := cmd.Output()
		cancel()

		if err != nil {
			eventChan <- ScanEvent{Type: "error", Message: fmt.Sprintf("Nmap error: %v", err)}
		} else {
			eventChan <- ScanEvent{Type: "nmap", Data: string(out)}
			fullData["nmap_scan"] = string(out)

			// Parse open ports from nmap output and run native banner verification
			nmapScanLines := strings.Split(string(out), "\n")
			var nativeBanners []BannerResult
			
			for _, line := range nmapScanLines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						portProto := parts[0]
						nmapService := parts[2]
						nmapVersion := ""
						if len(parts) > 3 {
							nmapVersion = strings.Join(parts[3:], " ")
						}

						portNum := 0
						fmt.Sscanf(portProto, "%d/tcp", &portNum)

						if portNum > 0 {
							eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Running native banner verification on port %d...", portNum)}
							banner, resolvedType := GrabTCPBanner(target, portNum)
							
							resolvedService, status := VerifyBannerConsensus(nmapService, nmapVersion, banner, resolvedType)
							
							res := BannerResult{
								Port:         portNum,
								Protocol:     "tcp",
								RawBanner:    banner,
								ServiceType:  resolvedService,
								Verification: status,
							}
							nativeBanners = append(nativeBanners, res)

							if status == "MATCH" {
								eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("[🛡️ SERVICE DOUBLE-VERIFIED] Port %d: Nmap (%s) | Native Grabber (%s) - VALIDATED", portNum, nmapService, banner)}
							} else if status == "DISCREPANCY" {
								eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("[⚠️ SERVICE DISCREPANCY] Port %d: Nmap (%s) | Native Grabber (%s) - VERIFICATION WARNING", portNum, nmapService, banner)}
							} else if status == "NATIVE_ONLY" {
								eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("[💡 SERVICE DISCOVERED NATIVELY] Port %d resolved: %s (Banner: %s)", portNum, resolvedService, banner)}
							}
						}
					}
				}
			}
			fullData["native_banners"] = nativeBanners
		}
	}

	// 3. Whatweb
	var technologies []interface{}
	whatwebPath, err := setup.ResolveToolPath("whatweb")
	if err != nil {
		eventChan <- ScanEvent{Type: "info", Message: "WhatWeb not installed. Skipping technology detection."}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "Running WhatWeb..."}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		
		whatwebArgs := []string{target, "--log-json=-"}
		if config.Proxy != "" {
			whatwebArgs = append(whatwebArgs, "--proxy", config.Proxy)
		}
		if config.UserAgent != "" {
			whatwebArgs = append(whatwebArgs, "--user-agent", config.UserAgent)
		}
		
		cmd := exec.CommandContext(ctx, whatwebPath, whatwebArgs...)
		out, err := cmd.Output()
		cancel()
		
		if err == nil && len(out) > 0 {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var t interface{}
				if json.Unmarshal([]byte(line), &t) == nil {
					technologies = append(technologies, t)
				}
			}
			eventChan <- ScanEvent{Type: "technology", Data: technologies}
			fullData["technologies"] = technologies
		}
	}

	// 3.5 Katana Web Crawler
	var crawledURLs []string
	katanaPath, err := setup.ResolveToolPath("katana")
	if err != nil {
		eventChan <- ScanEvent{Type: "info", Message: "Katana not installed. Skipping web spider crawling."}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "Running Katana Web Crawler..."}
		
		scheme := "http"
		nmapScanText, _ := fullData["nmap_scan"].(string)
		if strings.Contains(strings.ToLower(nmapScanText), "443/tcp open") {
			scheme = "https"
		}

		seedURLs := []string{scheme + "://" + target}
		for _, sub := range subdomains {
			seedURLs = append(seedURLs, scheme + "://" + sub)
		}

		// Write seed targets to a temporary file
		seedFile, err := ioutil.TempFile("", "katana_seeds_*.txt")
		if err == nil {
			seedPath := seedFile.Name()
			for _, url := range seedURLs {
				seedFile.WriteString(url + "\n")
			}
			seedFile.Close()
			defer os.Remove(seedPath)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			katanaArgs := []string{"-list", seedPath, "-jc", "-d", "2", "-silent"}
			
			if config.Proxy != "" {
				katanaArgs = append(katanaArgs, "-proxy", config.Proxy)
			}
			if config.UserAgent != "" {
				katanaArgs = append(katanaArgs, "-H", fmt.Sprintf("User-Agent: %s", config.UserAgent))
			} else {
				katanaArgs = append(katanaArgs, "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			}
			if config.RateLimit > 0 {
				katanaArgs = append(katanaArgs, "-rate-limit", fmt.Sprintf("%d", config.RateLimit))
			}
			
			cmd := exec.CommandContext(ctx, katanaPath, katanaArgs...)
			
			stdout, err := cmd.StdoutPipe()
			if err == nil {
				if err := cmd.Start(); err == nil {
					scanner := bufio.NewScanner(stdout)
					for scanner.Scan() {
						urlLine := strings.TrimSpace(scanner.Text())
						if urlLine != "" {
							crawledURLs = append(crawledURLs, urlLine)
							eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Spider Discovered URL: %s", urlLine)}
						}
					}
					cmd.Wait()
				}
			}
			cancel()
		}
	}
	fullData["crawled_urls"] = crawledURLs

	// 4. Nuclei
	var findings []interface{}
	nucleiPath, err := setup.ResolveToolPath("nuclei")
	if err != nil {
		eventChan <- ScanEvent{Type: "info", Message: "Nuclei not installed. Skipping vulnerability scanning."}
	} else {
		eventChan <- ScanEvent{Type: "info", Message: "Running Nuclei..."}
		tmpFile, err := ioutil.TempFile("", "nuclei_*.jsonl")
		if err != nil {
			eventChan <- ScanEvent{Type: "error", Message: "Failed to create temp file for nuclei"}
		} else {
			tmpPath := tmpFile.Name()
			tmpFile.Close()
			defer os.Remove(tmpPath)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			
			var nucleiArgs []string
			var targetListPath string
			
			if len(crawledURLs) > 0 {
				listFile, err := ioutil.TempFile("", "nuclei_targets_*.txt")
				if err == nil {
					targetListPath = listFile.Name()
					for _, url := range crawledURLs {
						listFile.WriteString(url + "\n")
					}
					listFile.Close()
					defer os.Remove(targetListPath)
					
					nucleiArgs = append(nucleiArgs, "-list", targetListPath)
					eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Feeding %d crawled spider targets to Nuclei...", len(crawledURLs))}
				} else {
					nucleiArgs = append(nucleiArgs, "-u", target)
				}
			} else {
				nucleiArgs = append(nucleiArgs, "-u", target)
			}
			
			// Append proxy, User-Agent, and rate limiting details
			if config.Proxy != "" {
				nucleiArgs = append(nucleiArgs, "-proxy", config.Proxy)
			}
			if config.UserAgent != "" {
				nucleiArgs = append(nucleiArgs, "-H", fmt.Sprintf("User-Agent: %s", config.UserAgent))
			} else {
				nucleiArgs = append(nucleiArgs, "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			}
			if config.RateLimit > 0 {
				nucleiArgs = append(nucleiArgs, "-rate-limit", fmt.Sprintf("%d", config.RateLimit))
			}
			
			// Custom template execution support
			if config.CustomTemplate != "" {
				home, _ := os.UserHomeDir()
				templatesDir := filepath.Join(home, ".vulnsight", "custom-templates")
				safeName := filepath.Base(config.CustomTemplate)
				templatePath := filepath.Join(templatesDir, safeName)
				
				if _, err := os.Stat(templatePath); err == nil {
					nucleiArgs = append(nucleiArgs, "-t", templatePath)
					eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Executing custom template: %s", safeName)}
				} else {
					eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("Template %s not found locally. Running default sets.", safeName)}
				}
			}
			
			nucleiArgs = append(nucleiArgs, "-jsonl", "-o", tmpPath)
			cmd := exec.CommandContext(ctx, nucleiPath, nucleiArgs...)
			cmd.Run()
			cancel()

			// Read findings
			file, err := os.Open(tmpPath)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					var f interface{}
					if json.Unmarshal(scanner.Bytes(), &f) == nil {
						findings = append(findings, f)
						eventChan <- ScanEvent{Type: "nuclei", Data: f}
					}
				}
				file.Close()
			}
			fullData["nuclei_findings"] = findings
		}
	}

	// 4.5 Native Web Leak Scan
	eventChan <- ScanEvent{Type: "info", Message: "Running proprietary VulnSightAI Web Leak scan..."}
	scheme := "http"
	nmapScanText, _ := fullData["nmap_scan"].(string)
	if strings.Contains(strings.ToLower(nmapScanText), "443/tcp open") {
		scheme = "https"
	}
	nativeLeaks := ScanWebLeaks(scheme+"://"+target, eventChan)
	fullData["native_leaks"] = nativeLeaks

	// Append native leaks to AI findings context for joint analysis
	for _, leak := range nativeLeaks {
		aiFinding := map[string]interface{}{
			"info": map[string]interface{}{
				"name":        leak.Type,
				"severity":    leak.Severity,
				"description": leak.Description,
			},
			"matched-at": scheme + "://" + target + leak.Path,
		}
		findings = append(findings, aiFinding)
	}

	// 4.6 Native CVE & MITRE ATT&CK Threat Correlation
	eventChan <- ScanEvent{Type: "info", Message: "Calculating CVE & MITRE ATT&CK Threat Correlation Matrix..."}
	nativeBanners, _ := fullData["native_banners"].([]BannerResult)
	correlations := CorrelateThreats(nativeBanners, nativeLeaks)
	fullData["cve_correlations"] = correlations

	// Stream correlation events
	for _, c := range correlations {
		eventChan <- ScanEvent{
			Type:    "cve",
			Data:    c,
			Message: fmt.Sprintf("[📊 THREAT CORRELATED] %s maps to %s (MITRE %s - %s)", c.Name, c.ID, c.MitreTechnique, c.MitreTactic),
		}
		
		aiFinding := map[string]interface{}{
			"info": map[string]interface{}{
				"name":        fmt.Sprintf("Correlated: %s (%s)", c.Name, c.ID),
				"severity":    "HIGH",
				"description": fmt.Sprintf("MITRE Tactic: %s, Technique: %s. %s", c.MitreTactic, c.MitreTechnique, c.Description),
			},
			"matched-at": c.ID,
		}
		findings = append(findings, aiFinding)
	}

	// 4.7 Native CISA KEV (Known Exploited Vulnerabilities) Active Threat checks
	eventChan <- ScanEvent{Type: "info", Message: "Syncing CISA KEV active zero-day threat catalog databases..."}
	kevAlerts := MatchKEV(correlations)
	fullData["kev_alerts"] = kevAlerts

	// Stream active KEV advisories
	for _, k := range kevAlerts {
		eventChan <- ScanEvent{
			Type:    "kev",
			Data:    k,
			Message: fmt.Sprintf("[🚨 CISA KEV ACTIVE THREAT] %s (%s) is actively exploited by threat actors!", k.Vulnerability, k.CVEID),
		}

		aiFinding := map[string]interface{}{
			"info": map[string]interface{}{
				"name":        fmt.Sprintf("🚨 ACTIVE IN THE WILD: %s (%s)", k.Vulnerability, k.CVEID),
				"severity":    "CRITICAL",
				"description": fmt.Sprintf("CISA KEV ALERT: %s. Required action: %s", k.Description, k.RequiredAction),
			},
			"matched-at": k.CVEID,
		}
		findings = append(findings, aiFinding)
	}

	// AI Agents
	eventChan <- ScanEvent{Type: "info", Message: fmt.Sprintf("AI (%s) is reviewing findings...", aiModel)}
	aiReport, err := agents.ExploitReviewAgent(findings, technologies, aiModel)
	if err != nil {
		fullData["ai_suggestions"] = "AI Review failed: " + err.Error()
		log.Println("AI Error:", err)
	} else {
		fullData["ai_suggestions"] = aiReport
		eventChan <- ScanEvent{Type: "info", Message: "AI Review Complete."}
	}

	// Done
	eventChan <- ScanEvent{Type: "done", Data: fullData, Message: "Scan complete"}
}
