package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gorilla/websocket"
	"regexp"
	"path/filepath"
	"os/exec"
	"runtime"
)

// ANSI terminal color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[1;31m"
	colorGreen  = "\033[1;32m"
	colorYellow = "\033[1;33m"
	colorBlue   = "\033[1;34m"
	colorCyan   = "\033[1;36m"
	colorGray   = "\033[0;37m"
	colorBold   = "\033[1m"
)

type ScanEvent struct {
	Type    string      `json:"type"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ScanResult struct {
	ID        int    `json:"id"`
	Target    string `json:"target"`
	Timestamp string `json:"timestamp"`
}

func main() {
	// Configure flag usage override
	flag.Usage = func() {
		printWelcomeBanner()
		printDetailedHelp()
	}

	// Global flags
	serverFlag := flag.String("server", "http://localhost:8080", "VulnSightAI engine server URL")
	apiKeyFlag := flag.String("api-key", "", "API key (X-API-Key header) if configured")
	modelFlag := flag.String("model", "", "AI model for exploit reviews (default: deepseek-coder:latest)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printWelcomeBanner()
		printShortUsage()
		os.Exit(0)
	}

	subcommand := args[0]
	server := strings.TrimSuffix(*serverFlag, "/")

	if subcommand != "completion" {
		printWelcomeBanner()
	}

	switch subcommand {
	case "help":
		printDetailedHelp()
	case "diagnostics":
		diagnosticsCommand(server, *apiKeyFlag)
	case "list":
		listCommand(server, *apiKeyFlag)
	case "report":
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: Please specify a scan ID (e.g. vulnsight-cli report 1)%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		scanID := args[1]
		outputFile := fmt.Sprintf("vulnsight_report_%s.html", scanID)
		if len(args) >= 3 {
			outputFile = args[2]
		}
		reportCommand(server, *apiKeyFlag, scanID, outputFile)
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		portsFlag := scanCmd.String("ports", "common", "Ports to scan (common, all, or custom ports like 80,443)")
		speedFlag := scanCmd.String("speed", "T3", "Scan speed (T1-T5)")
		depthFlag := scanCmd.String("depth", "fast", "Scan depth (fast, deep)")
		templateFlag := scanCmd.String("template", "", "Custom template filename to run")
		proxyFlag := scanCmd.String("proxy", "", "SOCKS5/HTTP proxy URL (e.g. socks5://127.0.0.1:9050)")
		userAgentFlag := scanCmd.String("user-agent", "", "Custom HTTP User-Agent request header")
		rateLimitFlag := scanCmd.Int("rate-limit", 0, "Custom scan request rate limit (RPS)")
		
		scanCmd.Parse(args[1:])
		scanArgs := scanCmd.Args()
		if len(scanArgs) < 1 {
			fmt.Printf("%s[!] Error: Please specify a target domain or IP (e.g. vulnsight-cli scan 127.0.0.1)%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		target := scanArgs[0]
		scanCommand(server, *apiKeyFlag, target, *modelFlag, *portsFlag, *speedFlag, *depthFlag, *templateFlag, *proxyFlag, *userAgentFlag, *rateLimitFlag)
	case "show":
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: Please specify a scan ID (e.g. vulnsight-cli show 5)%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		scanID := args[1]
		showCommand(server, *apiKeyFlag, scanID)
	case "template":
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: Please specify template action (list, validate, save)%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		action := args[1]
		switch action {
		case "list":
			templateListCommand(server, *apiKeyFlag)
		case "validate":
			if len(args) < 3 {
				fmt.Printf("%s[!] Error: Please specify path to template file%s\n", colorRed, colorReset)
				os.Exit(1)
			}
			templateValidateCommand(server, *apiKeyFlag, args[2])
		case "save":
			if len(args) < 3 {
				fmt.Printf("%s[!] Error: Please specify path to template file%s\n", colorRed, colorReset)
				os.Exit(1)
			}
			name := ""
			if len(args) >= 4 {
				name = args[3]
			}
			templateSaveCommand(server, *apiKeyFlag, args[2], name)
		default:
			fmt.Printf("%s[!] Error: Unknown template action '%s'%s\n", colorRed, action, colorReset)
			os.Exit(1)
		}
	case "setup":
		setupCommand(server, *apiKeyFlag)
	case "uninstall", "reset":
		uninstallCommand(server, *apiKeyFlag)
	case "service":
		if len(args) < 2 {
			fmt.Printf("%s[!] Error: Please specify service action (install, remove)%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		action := args[1]
		if action == "install" {
			serviceInstallCommand()
		} else if action == "remove" {
			serviceRemoveCommand()
		} else {
			fmt.Printf("%s[!] Error: Unknown service action '%s'%s\n", colorRed, action, colorReset)
			os.Exit(1)
		}
	case "completion":
		completionCommand()
	case "update":
		updateCommand()
	default:
		fmt.Printf("%s[!] Error: Unknown command '%s'%s\n", colorRed, subcommand, colorReset)
		printDetailedHelp()
		os.Exit(1)
	}
}

func printWelcomeBanner() {
	// Snake ASCII art in green, VulnSight in cyan/red, frame in dark grey
	snakeColor := "\033[1;32m" // Bright Green
	textColor := "\033[1;36m"  // Cyan
	accColor := "\033[1;31m"   // Bright Red
	grayColor := "\033[1;30m"  // Dark Gray
	reset := "\033[0m"

	// Define banner lines
	lines := []string{
		grayColor + " 💀 [BLACKHAT MATRIX RECON ENGINE ACTIVE] 💀" + reset,
		snakeColor + "        .---.  .---.    " + textColor + " _     _  _  _       ____  _       _     _   " + reset,
		snakeColor + "       /     \\/     \\   " + textColor + "| |   | || || |     / ___|(_) __ _| |__ | |_ " + reset,
		snakeColor + "      |  /\\   /\\   /|   " + textColor + "| |   | || || |     \\___ \\| |/ _` | '_ \\| __|" + reset,
		snakeColor + "      |  \\ \\_/ /  / |   " + textColor + "| |___| || || |___   ___) | | (_| | | | | |_ " + reset,
		snakeColor + "       \\  \\   /  /  /   " + textColor + "|_____|_||_||_____| |____/|_|\\__, |_| |_|\\__|" + reset,
		snakeColor + "        \\  \\_/  /  /    " + grayColor + "                             |___/           " + reset,
		snakeColor + "         \\     /  /     " + accColor + "  ==[ VulnSightAI v2.0.1 - Red Team Edition ]==" + reset,
		snakeColor + "          \\___/  /      " + grayColor + "  ⚡ Powered by hackwithsaket                 " + reset,
		snakeColor + "              \\_/       " + reset,
		grayColor + " ⚡========================================================================⚡" + reset,
	}

	// Print lines with a micro-delay to simulate a cool hacking launch sequence
	for _, line := range lines {
		fmt.Println(line)
		time.Sleep(35 * time.Millisecond)
	}

	// Dynamic interactive matrix loader sequence to look high level
	loaderText := []string{
		" [*] Connecting matrix socket interfaces... ",
		" [*] Syncing local neural model endpoints... ",
		" [*] Loading Nuclei/Nmap signature database... ",
	}

	for _, text := range loaderText {
		fmt.Print(grayColor + text + reset)
		time.Sleep(120 * time.Millisecond)
		fmt.Println(snakeColor + "[SUCCESS]" + reset)
	}
	fmt.Println()
}

func printShortUsage() {
	fmt.Printf("%sUSAGE:%s\n", colorBold, colorReset)
	fmt.Println("  vulnsight-cli <command> [arguments]")
	fmt.Println()
	fmt.Printf("%sCORE COMMANDS:%s\n", colorBold, colorReset)
	fmt.Printf("  %-25s %s\n", colorCyan+"scan <target>"+colorReset, "Trigger a security scan on a target")
	fmt.Printf("  %-25s %s\n", colorCyan+"list"+colorReset, "List past scan records")
	fmt.Printf("  %-25s %s\n", colorCyan+"show <scan_id>"+colorReset, "Inspect findings for a scan ID")
	fmt.Printf("  %-25s %s\n", colorCyan+"update"+colorReset, "Auto-update VulnSightAI binary")
	fmt.Printf("  %-25s %s\n", colorCyan+"uninstall"+colorReset, "Cleanly remove the framework")
	fmt.Println()
	fmt.Printf("%sHELP & DOCS:%s\n", colorBold, colorReset)
	fmt.Println("  For detailed help & custom flags, execute: " + colorCyan + "vulnsight-cli --help" + colorReset + " or " + colorCyan + "vulnsight-cli help" + colorReset)
	fmt.Println()
}

func printDetailedHelp() {
	fmt.Printf("\n%sUSAGE:%s\n", colorBold, colorReset)
	fmt.Println("  vulnsight-cli [global flags] <command> [arguments]")

	fmt.Printf("\n%sGLOBAL FLAGS:%s\n", colorBold, colorReset)
	fmt.Println("  --server <url>       VulnSightAI engine server URL (default: http://localhost:8080)")
	fmt.Println("  --api-key <key>      API token header (X-API-Key) for backend authorization")
	fmt.Println("  --model <name>       Ollama model target for AI exploit reviews (e.g. deepseek-coder:latest)")
	fmt.Println("  -h, --help           Show this comprehensive help menu")

	fmt.Printf("\n%sCOMMANDS:%s\n", colorBold, colorReset)
	fmt.Printf("  %sscan [flags] <target>%s\n", colorCyan, colorReset)
	fmt.Println("    Triggers a live vulnerability scan on the server and streams telemetry reports in real-time.")
	fmt.Println("    Flags:")
	fmt.Println("      --ports <range>    Ports to scan (common, all, or custom ports like 80,443) [default: common]")
	fmt.Println("      --speed <level>    Nmap speed level T1 (paranoid/slow) to T5 (insane) [default: T3]")
	fmt.Println("      --depth <mode>     Subdomain brute-forcing mode (fast, deep) [default: fast]")
	fmt.Println("      --template <name>  Custom Nuclei template filename to execute")
	fmt.Println("      --proxy <url>      SOCKS5/HTTP proxy URL (e.g. socks5://127.0.0.1:9050)")
	fmt.Println("      --user-agent <ua>  Custom User-Agent header value to send in HTTP requests")
	fmt.Println("      --rate-limit <rps> Limit scanning requests per second (RPS) [default: 0 / unlimited]")
	fmt.Println("    Examples:")
	fmt.Println("      vulnsight-cli scan 127.0.0.1")
	fmt.Println("      vulnsight-cli scan --ports 80,443 --speed T4 --depth deep target.com")
	fmt.Println("      vulnsight-cli scan --proxy socks5://127.0.0.1:9050 --user-agent \"Mozilla/5.0\" target.com")
	
	fmt.Printf("\n  %slist%s\n", colorCyan, colorReset)
	fmt.Println("    Retrieves all past scan records archived in the SQLite database and prints them in a table.")
	fmt.Println("    Example: vulnsight-cli list")

	fmt.Printf("\n  %sreport <scan_id> [output_file]%s\n", colorCyan, colorReset)
	fmt.Println("    Downloads the compiled HTML vulnerability sheet for a specific scan ID.")
	fmt.Println("    Example: vulnsight-cli report 1")
	fmt.Println("             vulnsight-cli report 2 server_check_report.html")

	fmt.Printf("\n  %sshow <scan_id>%s\n", colorCyan, colorReset)
	fmt.Println("    Retrieves parsed scan details (Nmap tables, Nuclei threats, AI advice) and renders them in the terminal.")
	fmt.Println("    Example: vulnsight-cli show 5")

	fmt.Printf("\n  %sdiagnostics%s\n", colorCyan, colorReset)
	fmt.Println("    Checks the health status of backend scanning tools (Nmap, Nuclei, Subfinder, Katana, WhatWeb, Ollama).")
	fmt.Println("    Example: vulnsight-cli diagnostics")

	fmt.Printf("\n  %ssetup%s\n", colorCyan, colorReset)
	fmt.Println("    Runs the automated tool bootstrapper downloading and configuring missing binaries.")
	fmt.Println("    Example: vulnsight-cli setup")

	fmt.Printf("\n  %stemplate <action> [arguments]%s\n", colorCyan, colorReset)
	fmt.Println("    Manages custom Nuclei vulnerability scanning templates.")
	fmt.Println("    Actions:")
	fmt.Println("      list                          Lists all saved custom templates in the framework directory")
	fmt.Println("      validate <file>               Parses and validates Nuclei template YAML schema structure")
	fmt.Println("      save <file> [dest_name]       Saves a local YAML file to the framework custom templates bank")
	fmt.Println("    Examples:")
	fmt.Println("      vulnsight-cli template list")
	fmt.Println("      vulnsight-cli template validate checks/sqli-detect.yaml")
	fmt.Println("      vulnsight-cli template save checks/xss-detect.yaml custom-xss.yaml")

	fmt.Printf("\n  %suninstall / reset%s\n", colorCyan, colorReset)
	fmt.Println("    Cleans and completely removes local binaries and configuration directory ~/.vulnsight.")
	fmt.Println("    Example: vulnsight-cli uninstall")

	fmt.Printf("\n  %sservice <install/remove>%s\n", colorCyan, colorReset)
	fmt.Println("    Configures and installs the VulnSightAI Backend as a Systemd service (Linux auto-boot).")
	fmt.Println("    Example: sudo vulnsight-cli service install")

	fmt.Printf("\n  %supdate%s\n", colorCyan, colorReset)
	fmt.Println("    Checks GitHub for the latest release and auto-updates the running binary in-place.")
	fmt.Println("    Example: vulnsight-cli update")

	fmt.Printf("\n  %scompletion%s\n", colorCyan, colorReset)
	fmt.Println("    Generates Shell Autocomplete script configuration for Bash.")
	fmt.Println("    Example: source <(vulnsight-cli completion)")

	fmt.Println("\n===========================================================")
	fmt.Printf("  %sFor security scanning, ensure you have explicit permission on the target.%s\n", colorYellow, colorReset)
	fmt.Println("===========================================================")
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func updateCommand() {
	fmt.Printf("%s[*] Checking for updates from GitHub...%s\n", colorCyan, colorReset)
	
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/pingsaketchoudhary/VulnSightAI/releases/latest")
	if err != nil {
		fmt.Printf("%s[!] Error fetching latest release: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s[!] GitHub API returned status code %d%s\n", colorRed, resp.StatusCode, colorReset)
		return
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Printf("%s[!] Error decoding release JSON: %v%s\n", colorRed, err, colorReset)
		return
	}

	currentVersion := "v2.0.1"
	fmt.Printf("%s[*] Current version: %s | Latest version: %s%s\n", colorGray, currentVersion, release.TagName, colorReset)

	if release.TagName == currentVersion {
		fmt.Printf("%s[+] VulnSightAI is already up to date!%s\n", colorGreen, colorReset)
		return
	}

	// Determine asset name to look for
	var targetAsset string
	switch runtime.GOOS {
	case "linux":
		targetAsset = "vulnsight-cli"
	case "darwin":
		targetAsset = "vulnsight-cli-mac"
	case "windows":
		targetAsset = "vulnsight-cli.exe"
	default:
		fmt.Printf("%s[!] Unsupported OS for auto-update: %s%s\n", colorRed, runtime.GOOS, colorReset)
		return
	}

	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == targetAsset {
			downloadURL = asset.DownloadURL
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("%s[!] Could not find matching precompiled binary asset '%s' in the latest release.%s\n", colorRed, targetAsset, colorReset)
		return
	}

	fmt.Printf("%s[*] Downloading update from: %s...%s\n", colorCyan, downloadURL, colorReset)

	// Get path to current executable
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("%s[!] Error getting current executable path: %v%s\n", colorRed, err, colorReset)
		return
	}

	// Resolve symlinks if any
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		fmt.Printf("%s[!] Error resolving executable path symlinks: %v%s\n", colorRed, err, colorReset)
		return
	}

	// Download new binary
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		fmt.Printf("%s[!] Error creating request: %v%s\n", colorRed, err, colorReset)
		return
	}

	downloadResp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[!] Error downloading asset: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		fmt.Printf("%s[!] HTTP download returned status %d%s\n", colorRed, downloadResp.StatusCode, colorReset)
		return
	}

	// Create a temp file in the same directory as the executable to ensure they are on the same filesystem (so rename works)
	tempFile, err := os.CreateTemp(filepath.Dir(execPath), "vulnsight-update-")
	if err != nil {
		fmt.Printf("%s[!] Error creating temp file: %v%s\n", colorRed, err, colorReset)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // Clean up temp file if rename fails
	defer tempFile.Close()

	// Write response to temp file
	_, err = io.Copy(tempFile, downloadResp.Body)
	if err != nil {
		fmt.Printf("%s[!] Error writing downloaded binary: %v%s\n", colorRed, err, colorReset)
		return
	}
	tempFile.Close()

	// Set execute permissions
	err = os.Chmod(tempPath, 0755)
	if err != nil {
		fmt.Printf("%s[!] Error setting execute permissions on temp file: %v%s\n", colorRed, err, colorReset)
		return
	}

	// Rename temp file to current executable
	if runtime.GOOS == "windows" {
		// On Windows, rename existing running file first, then write new one
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath) // Delete previous .old if exists
		err = os.Rename(execPath, oldPath)
		if err != nil {
			fmt.Printf("%s[!] Error renaming running executable: %v%s\n", colorRed, err, colorReset)
			return
		}
		err = os.Rename(tempPath, execPath)
		if err != nil {
			// Rollback rename
			_ = os.Rename(oldPath, execPath)
			fmt.Printf("%s[!] Error renaming new executable: %v%s\n", colorRed, err, colorReset)
			return
		}
		// Try to remove the old file (often fails since it's running, but it's fine, it will disappear on reboot/next command)
		_ = os.Remove(oldPath)
	} else {
		// On Linux/macOS, we can overwrite it directly
		err = os.Rename(tempPath, execPath)
		if err != nil {
			fmt.Printf("%s[!] Error replacing executable: %v%s\n", colorRed, err, colorReset)
			return
		}
	}

	fmt.Printf("%s[+] VulnSightAI successfully updated to %s!%s\n", colorGreen, release.TagName, colorReset)
}

func makeRequest(method, url, apiKey string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func diagnosticsCommand(server, apiKey string) {
	url := fmt.Sprintf("%s/api/diagnostics", server)
	resp, err := makeRequest("GET", url, apiKey, nil)
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Server returned error status: %d", resp.StatusCode)
	}

	var diag map[string]bool
	if err := json.NewDecoder(resp.Body).Decode(&diag); err != nil {
		log.Fatalf("Error decoding response: %v", err)
	}

	fmt.Printf("\n%s[+] Backend Systems Diagnostics Checklist:%s\n", colorBold, colorReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Service\tStatus")
	fmt.Fprintln(w, "-------\t------")

	for tool, ok := range diag {
		statusStr := fmt.Sprintf("%s[✓] Installed%s", colorGreen, colorReset)
		if !ok {
			statusStr = fmt.Sprintf("%s[✗] Missing / Offline%s", colorRed, colorReset)
		}
		fmt.Fprintf(w, "%s\t%s\n", tool, statusStr)
	}
	w.Flush()
	fmt.Println()
}

func listCommand(server, apiKey string) {
	url := fmt.Sprintf("%s/api/scans", server)
	resp, err := makeRequest("GET", url, apiKey, nil)
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Server returned error status: %d", resp.StatusCode)
	}

	var scans []ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&scans); err != nil {
		// If scans list is null
		scans = []ScanResult{}
	}

	fmt.Printf("\n%s[+] Archived Scan Operations History:%s\n", colorBold, colorReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "Scan ID\tTarget Asset\tScanned Timestamp")
	fmt.Fprintln(w, "-------\t------------\t-----------------")

	for _, s := range scans {
		fmt.Fprintf(w, "%d\t%s\t%s\n", s.ID, s.Target, s.Timestamp)
	}
	w.Flush()
	fmt.Println()
}

func reportCommand(server, apiKey, scanID, outputFile string) {
	url := fmt.Sprintf("%s/api/report/%s", server, scanID)
	resp, err := makeRequest("GET", url, apiKey, nil)
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Failed to fetch report (Status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create report file locally: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatalf("Error downloading report content: %v", err)
	}

	fmt.Printf("%s[✓] Report downloaded successfully: %s%s\n", colorGreen, outputFile, colorReset)
}

func scanCommand(server, apiKey, target, model, ports, speed, depth, template, proxy, userAgent string, rateLimit int) {
	url := fmt.Sprintf("%s/api/scan", server)

	reqPayload := map[string]interface{}{
		"target":          target,
		"ports":           ports,
		"speed":           speed,
		"depth":           depth,
		"custom_template": template,
		"proxy":           proxy,
		"user_agent":      userAgent,
		"rate_limit":      rateLimit,
	}
	if model != "" {
		reqPayload["model"] = model
	}

	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		log.Fatalf("Error preparing request: %v", err)
	}

	resp, err := makeRequest("POST", url, apiKey, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to start scan: %v (make sure the backend engine is running)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Engine rejected scan: %s", string(bodyBytes))
	}

	var startResp struct {
		ScanID string `json:"scan_id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&startResp); err != nil {
		log.Fatalf("Failed to parse start response: %v", err)
	}

	fmt.Printf("%s[*] Scan engaged successfully.%s\n", colorCyan, colorReset)
	fmt.Printf("%s[*] Scan ID: %s%s\n", colorCyan, startResp.ScanID, colorReset)
	fmt.Printf("%s[*] Telemetry matrix streaming initialized...%s\n\n", colorCyan, colorReset)

	// Build WebSocket URL
	wsURL := strings.Replace(server, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = fmt.Sprintf("%s/api/ws/scan/%s", wsURL, startResp.ScanID)

	header := http.Header{}
	if apiKey != "" {
		header.Set("X-API-Key", apiKey)
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		log.Fatalf("WebSocket connection failed: %v", err)
	}
	defer conn.Close()

	for {
		var event ScanEvent
		err := conn.ReadJSON(&event)
		if err != nil {
			// If connection closes cleanly
			break
		}

		switch event.Type {
		case "subdomain":
			fmt.Printf("%s[+] Subdomain: %s%s\n", colorBlue, event.Data, colorReset)
		case "nmap":
			fmt.Printf("%s[NMAP] Service Scan Results:%s\n%s\n", colorCyan, colorReset, event.Data)
		case "technology":
			fmt.Printf("%s[TECH] Tech Fingerprints: %s%s\n", colorYellow, event.Data, colorReset)
		case "nuclei":
			// Attempt to cast Data map to format severity/name
			var name, severity string
			if m, ok := event.Data.(map[string]interface{}); ok {
				name, _ = m["info"].(map[string]interface{})["name"].(string)
				severity, _ = m["info"].(map[string]interface{})["severity"].(string)
			}
			if name == "" {
				name = "Detected threat"
			}
			if severity == "" {
				severity = "info"
			}
			fmt.Printf("%s[VULN] [%s] %s%s\n", colorRed, strings.ToUpper(severity), name, colorReset)
		case "leak":
			var leakType, severity, path, evidence string
			if m, ok := event.Data.(map[string]interface{}); ok {
				leakType, _ = m["type"].(string)
				severity, _ = m["severity"].(string)
				path, _ = m["path"].(string)
				evidence, _ = m["evidence"].(string)
			}
			fmt.Printf("%s[🔥 NATIVE LEAK] [%s] %s (Path: %s)%s\n", colorRed, strings.ToUpper(severity), leakType, path, colorReset)
			if evidence != "" {
				indentedEv := "  | " + strings.ReplaceAll(strings.TrimSpace(evidence), "\n", "\n  | ")
				fmt.Printf("%s%s%s\n", colorGray, indentedEv, colorReset)
			}
		case "cve":
			var cveID, cveName, tactic, technique string
			var cvss, epss float64
			if m, ok := event.Data.(map[string]interface{}); ok {
				cveID, _ = m["id"].(string)
				cveName, _ = m["name"].(string)
				tactic, _ = m["mitre_tactic"].(string)
				technique, _ = m["mitre_technique"].(string)
				cvss, _ = m["cvss"].(float64)
				epss, _ = m["epss"].(float64)
			}
			fmt.Printf("%s[📊 MITRE CORRELATED] [%s] %s | Tactic: %s (Technique: %s) | CVSS: %.1f | EPSS: %.0f%%%s\n", 
				colorCyan, cveID, cveName, tactic, technique, cvss, epss*100, colorReset)
		case "kev":
			var cveID, vulnName, desc, action string
			if m, ok := event.Data.(map[string]interface{}); ok {
				cveID, _ = m["cve_id"].(string)
				vulnName, _ = m["vulnerability_name"].(string)
				desc, _ = m["description"].(string)
				action, _ = m["required_action"].(string)
			}
			fmt.Printf("%s[🚨 CISA KEV ALERT] [%s] %s%s\n", colorRed, cveID, vulnName, colorReset)
			fmt.Printf("%s  Description: %s\n  Action Required: %s%s\n", colorRed, desc, action, colorReset)
		case "info":
			fmt.Printf("%s[*] %s%s\n", colorGray, event.Message, colorReset)
		case "done":
			fmt.Printf("\n%s[✓] %s%s\n", colorGreen, event.Message, colorReset)
			// Print final AI review suggestions if present
			if m, ok := event.Data.(map[string]interface{}); ok {
				if sugg, ok := m["ai_suggestions"].(string); ok && sugg != "" {
					fmt.Printf("\n%s🛡️  AI Mitigation Suggestions: %s\n%s\n", colorGreen, colorReset, sugg)
				}
			}
			return
		case "error":
			fmt.Printf("%s[!] Scan Error: %s%s\n", colorRed, event.Message, colorReset)
			return
		}
	}
}

func setupCommand(server, apiKey string) {
	autoInstallSystemDependencies()
	fmt.Printf("%s[*] Initiating automated framework dependency bootstrapper...%s\n", colorCyan, colorReset)
	fmt.Printf("%s[*] Fetching latest cross-compiled releases from GitHub...%s\n", colorCyan, colorReset)

	url := fmt.Sprintf("%s/api/setup", server)
	// Give it a higher timeout (3 minutes) because it downloads files
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatalf("Failed to prepare request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Communication error: %v (make sure the backend engine is running)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Setup failed (Status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	type ToolSetupStatus struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}

	var results map[string]ToolSetupStatus
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		log.Fatalf("Failed to parse setup status response: %v", err)
	}

	fmt.Printf("\n%s[+] Bootstrapper Installation Summary:%s\n", colorBold, colorReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Service\tStatus\tDetail")
	fmt.Fprintln(w, "-------\t------\t------")

	for tool, res := range results {
		statusStr := fmt.Sprintf("%s[✓] Installed%s", colorGreen, colorReset)
		detail := "Successfully unzipped and linked to ~/.vulnsight/bin/"
		if res.Status == "failed" {
			statusStr = fmt.Sprintf("%s[✗] Failed%s", colorRed, colorReset)
			detail = res.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", tool, statusStr, detail)
	}
	w.Flush()
	fmt.Println()
}

func showCommand(server, apiKey, scanID string) {
	fmt.Printf("%s[*] Querying scan record %s data...%s\n", colorCyan, scanID, colorReset)

	url := fmt.Sprintf("%s/api/scan/%s", server, scanID)
	resp, err := makeRequest("GET", url, apiKey, nil)
	if err != nil {
		log.Fatalf("Communication error: %v (make sure the backend engine is running)", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Retrieval failed (Status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	type ScanDetail struct {
		AISuggestions  string        `json:"ai_suggestions"`
		NmapScan       string        `json:"nmap_scan"`
		Subdomains     []string      `json:"subdomains"`
		Technologies   []interface{} `json:"technologies"`
		NucleiFindings []interface{} `json:"nuclei_findings"`
	}

	var detail ScanDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		log.Fatalf("Failed to decode scan details JSON: %v", err)
	}

	fmt.Printf("\n%s===========================================================%s\n", colorBold, colorReset)
	fmt.Printf("  %s🛡️  VulnSightAI Security Assessment Report: ID %s%s\n", colorBold, scanID, colorReset)
	fmt.Printf("%s===========================================================%s\n", colorBold, colorReset)

	// Subdomains
	if len(detail.Subdomains) > 0 {
		fmt.Printf("\n%s[🌐] Discovered Subdomain Namespace:%s\n", colorBold, colorReset)
		fmt.Printf("  %s%s%s\n", colorCyan, strings.Join(detail.Subdomains, ", "), colorReset)
	}

	// Technologies
	if len(detail.Technologies) > 0 {
		fmt.Printf("\n%s[💻] Technology Fingerprints:%s\n", colorBold, colorReset)
		var techTags []string
		for _, t := range detail.Technologies {
			if tMap, ok := t.(map[string]interface{}); ok {
				name, _ := tMap["name"].(string)
				version, _ := tMap["version"].(string)
				tag := name
				if version != "" {
					tag += " (v" + version + ")"
				}
				techTags = append(techTags, tag)
			} else if tStr, ok := t.(string); ok {
				techTags = append(techTags, tStr)
			}
		}
		fmt.Printf("  %s%s%s\n", colorYellow, strings.Join(techTags, ", "), colorReset)
	}

	// Nmap Ports Table
	if detail.NmapScan != "" {
		fmt.Printf("\n%s[🔌] Open Network Ports Table:%s\n", colorBold, colorReset)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Port/Protocol\tState\tService\tVersion")
		fmt.Fprintln(w, "-------------\t-----\t-------\t-------")

		lines := strings.Split(detail.NmapScan, "\n")
		re := regexp.MustCompile(`^(\d+/\w+)\s+(\w+)\s+(\S+)\s*(.*)$`)
		portsFound := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 4 {
				portsFound = true
				version := ""
				if len(matches) > 4 {
					version = strings.TrimSpace(matches[4])
				}
				port := matches[1]
				state := matches[2]
				service := matches[3]

				stateColor := colorGreen
				if state != "open" {
					stateColor = colorGray
				}
				fmt.Fprintf(w, "%s\t%s%s%s\t%s\t%s\n", port, stateColor, state, colorReset, service, version)
			}
		}
		w.Flush()
		if !portsFound {
			fmt.Println("  No active open ports parsed from text output.")
		}
	}

	// Threat Index
	fmt.Printf("\n%s[🔍] Threat & Vulnerability Index:%s\n", colorBold, colorReset)
	if len(detail.NucleiFindings) == 0 {
		fmt.Printf("  %s[✓] No active vulnerabilities detected by standard scans.%s\n", colorGreen, colorReset)
	} else {
		for _, f := range detail.NucleiFindings {
			if fMap, ok := f.(map[string]interface{}); ok {
				info, _ := fMap["info"].(map[string]interface{})
				name, _ := info["name"].(string)
				severity, _ := info["severity"].(string)
				matchedAt, _ := fMap["matched-at"].(string)

				sevColor := colorGray
				switch strings.ToUpper(severity) {
				case "CRITICAL", "HIGH":
					sevColor = colorRed
				case "MEDIUM":
					sevColor = colorYellow
				case "LOW":
					sevColor = colorBlue
				case "INFO":
					sevColor = colorCyan
				}
				fmt.Printf("  %s[%s]%s %s %s(at %s)%s\n", sevColor, strings.ToUpper(severity), colorReset, name, colorGray, matchedAt, colorReset)
			}
		}
	}

	// AI Suggestions
	if detail.AISuggestions != "" {
		fmt.Printf("\n%s[🤖] AI Security Recommendations:%s\n", colorBold, colorReset)
		fmt.Println("-----------------------------------------------------------")
		fmt.Println(detail.AISuggestions)
		fmt.Println("-----------------------------------------------------------")
	}
	fmt.Println()
}

func templateListCommand(server, apiKey string) {
	url := fmt.Sprintf("%s/api/templates", server)
	resp, err := makeRequest("GET", url, apiKey, nil)
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("List templates failed (Status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	type CLIResetMeta struct {
		Name     string `json:"name"`
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
	}

	var list []CLIResetMeta
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	fmt.Printf("\n%s[+] Saved Custom Templates Checklist:%s\n", colorBold, colorReset)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Filename\tTemplate ID\tSeverity\tTitle")
	fmt.Fprintln(w, "--------\t-----------\t--------\t-----")
	for _, t := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Name, t.ID, strings.ToUpper(t.Severity), t.Title)
	}
	w.Flush()
	fmt.Println()
}

func templateValidateCommand(server, apiKey, filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read template file: %v", err)
	}

	url := fmt.Sprintf("%s/api/templates/validate", server)
	reqPayload := map[string]string{
		"yaml": string(content),
	}
	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		log.Fatalf("Error preparing request: %v", err)
	}

	resp, err := makeRequest("POST", url, apiKey, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	type ValidateResp struct {
		Valid bool   `json:"valid"`
		Error string `json:"error,omitempty"`
	}
	var res ValidateResp
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Fatalf("Failed to parse validator response: %v", err)
	}

	if res.Valid {
		fmt.Printf("%s[✓] Nuclei Template is structurally VALID!%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[✗] Nuclei Template is INVALID: %s%s\n", colorRed, res.Error, colorReset)
	}
}

func templateSaveCommand(server, apiKey, filePath, destName string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read template file: %v", err)
	}

	if destName == "" {
		destName = filepath.Base(filePath)
	}

	url := fmt.Sprintf("%s/api/templates/save", server)
	reqPayload := map[string]string{
		"name": destName,
		"yaml": string(content),
	}
	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		log.Fatalf("Error preparing request: %v", err)
	}

	resp, err := makeRequest("POST", url, apiKey, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error communicating with server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Failed to save template (Status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	type SaveResp struct {
		Status string `json:"status"`
		Name   string `json:"name"`
		Path   string `json:"path"`
	}
	var res SaveResp
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	fmt.Printf("%s[✓] Template successfully saved as: %s%s\n", colorGreen, res.Name, colorReset)
	fmt.Printf("    Path: %s\n", res.Path)
}

func uninstallCommand(server, apiKey string) {
	fmt.Printf("%s[!] Warning: This will completely remove local binaries, cached templates, and databases under ~/.vulnsight.%s\n", colorYellow, colorReset)
	fmt.Print("Are you sure you want to proceed? (y/N): ")
	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println("Aborted.")
		return
	}

	// Reset backend
	url := fmt.Sprintf("%s/api/reset", server)
	resp, err := makeRequest("POST", url, apiKey, nil)
	if err == nil {
		resp.Body.Close()
	}

	// Reset CLI locally
	home, err := os.UserHomeDir()
	if err == nil {
		os.RemoveAll(filepath.Join(home, ".vulnsight"))
	}

	fmt.Printf("%s[✓] VulnSightAI local binaries and configurations deleted successfully.%s\n", colorGreen, colorReset)
}

func serviceInstallCommand() {
	cliPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to resolve executable path: %v", err)
	}
	cliDir := filepath.Dir(cliPath)
	
	backendPath := filepath.Join(cliDir, "vulnsight_bin")
	if _, err := os.Stat(backendPath); err != nil {
		cwd, _ := os.Getwd()
		backendPath = filepath.Join(cwd, "vulnsight_bin")
		if _, err := os.Stat(backendPath); err != nil {
			log.Fatalf("Failed to find backend executable 'vulnsight_bin'. Make sure it is compiled and placed in the current directory.")
		}
	}

	workingDir := filepath.Dir(backendPath)
	serviceContent := fmt.Sprintf(`[Unit]
Description=VulnSightAI Pentesting Framework Backend Daemon
After=network.target

[Service]
Type=simple
ExecStart=%s
WorkingDirectory=%s
Restart=always
User=root

[Install]
WantedBy=multi-user.target
`, backendPath, workingDir)

	servicePath := "/etc/systemd/system/vulnsight.service"
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		log.Fatalf("Failed to write systemd service file: %v. Make sure you are running as root/sudo.", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "vulnsight.service").Run()
	exec.Command("systemctl", "start", "vulnsight.service").Run()

	fmt.Printf("%s[✓] VulnSightAI Backend successfully installed as a Systemd service!%s\n", colorGreen, colorReset)
	fmt.Println("    Service Name: vulnsight.service")
	fmt.Println("    Command: systemctl status vulnsight")
}

func serviceRemoveCommand() {
	exec.Command("systemctl", "stop", "vulnsight.service").Run()
	exec.Command("systemctl", "disable", "vulnsight.service").Run()
	os.Remove("/etc/systemd/system/vulnsight.service")
	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Printf("%s[✓] VulnSightAI Backend Systemd service removed successfully.%s\n", colorGreen, colorReset)
}

func completionCommand() {
	script := `_vulnsight_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="diagnostics list report scan show template setup uninstall reset service completion"

    if [[ ${COMP_CWORD} -eq 1 ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        scan)
            local scan_opts="--ports --speed --depth --template"
            COMPREPLY=( $(compgen -W "${scan_opts}" -- ${cur}) )
            return 0
            ;;
        template)
            local temp_opts="list validate save"
            COMPREPLY=( $(compgen -W "${temp_opts}" -- ${cur}) )
            return 0
            ;;
        service)
            local svc_opts="install remove"
            COMPREPLY=( $(compgen -W "${svc_opts}" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _vulnsight_completion vulnsight-cli
`
	fmt.Print(script)
}

func autoInstallSystemDependencies() {
	// 1. Check Nmap
	if _, err := exec.LookPath("nmap"); err != nil {
		fmt.Printf("%s[!] System dependency 'nmap' is not installed on your system.%s\n", colorYellow, colorReset)
		fmt.Print("Would you like VulnSightAI to automatically install Nmap? (y/N): ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) == "y" {
			installNmap()
		}
	} else {
		fmt.Printf("%s[✓] Nmap is already active globally on your system.%s\n", colorGreen, colorReset)
	}

	// 2. Check WhatWeb
	if _, err := exec.LookPath("whatweb"); err != nil {
		fmt.Printf("%s[!] System dependency 'whatweb' is not installed on your system.%s\n", colorYellow, colorReset)
		fmt.Print("Would you like VulnSightAI to automatically install WhatWeb? (y/N): ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) == "y" {
			installWhatWeb()
		}
	} else {
		fmt.Printf("%s[✓] WhatWeb is already active globally on your system.%s\n", colorGreen, colorReset)
	}
}

func installNmap() {
	osName := runtime.GOOS
	switch osName {
	case "linux":
		if _, err := exec.LookPath("apt-get"); err == nil {
			runSudoCommand("apt-get", "update")
			runSudoCommand("apt-get", "install", "-y", "nmap")
		} else if _, err := exec.LookPath("pacman"); err == nil {
			runSudoCommand("pacman", "-S", "--noconfirm", "nmap")
		} else if _, err := exec.LookPath("dnf"); err == nil {
			runSudoCommand("dnf", "install", "-y", "nmap")
		} else {
			fmt.Println("No supported package manager (apt, pacman, dnf) found. Please install Nmap manually.")
		}
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			runCommandDirect("brew", "install", "nmap")
		} else {
			fmt.Println("Homebrew not found. Please install Homebrew (https://brew.sh) or Nmap manually.")
		}
	case "windows":
		if _, err := exec.LookPath("winget"); err == nil {
			runCommandDirect("winget", "install", "-e", "--id", "Insecure.Nmap")
		} else {
			fmt.Println("winget not found. Please download and run the Nmap installer from https://nmap.org/download.html")
		}
	default:
		fmt.Println("Unsupported OS for automated Nmap installation.")
	}
}

func installWhatWeb() {
	osName := runtime.GOOS
	switch osName {
	case "linux":
		if _, err := exec.LookPath("apt-get"); err == nil {
			runSudoCommand("apt-get", "install", "-y", "whatweb")
		} else {
			if _, err := exec.LookPath("gem"); err == nil {
				runSudoCommand("gem", "install", "whatweb")
			} else {
				fmt.Println("No supported package manager or Ruby gem installer found. Please install WhatWeb manually.")
			}
		}
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			runCommandDirect("brew", "install", "whatweb")
		} else {
			fmt.Println("Homebrew not found. Please install WhatWeb manually.")
		}
	case "windows":
		fmt.Println("WhatWeb automatic installation on Windows is not supported. Please run WhatWeb inside WSL or install Ruby and run: gem install whatweb")
	default:
		fmt.Println("Unsupported OS for automated WhatWeb installation.")
	}
}

func runSudoCommand(args ...string) {
	fmt.Printf("%s[*] Running: sudo %s%s\n", colorGray, strings.Join(args, " "), colorReset)
	cmdArgs := append([]string{"sudo"}, args...)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("%s[✗] Command execution failed: %v%s\n", colorRed, err, colorReset)
	}
}

func runCommandDirect(name string, args ...string) {
	fmt.Printf("%s[*] Running: %s %s%s\n", colorGray, name, strings.Join(args, " "), colorReset)
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("%s[✗] Command execution failed: %v%s\n", colorRed, err, colorReset)
	}
}
