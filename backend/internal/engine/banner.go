package engine

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type BannerResult struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	RawBanner    string `json:"raw_banner"`
	ServiceType  string `json:"service_type"`
	Verification string `json:"verification"` // "MATCH", "DISCREPANCY", or "NATIVE_ONLY"
}

// GrabTCPBanner establishes a raw socket connection to fetch service banner details.
func GrabTCPBanner(target string, port int) (string, string) {
	address := fmt.Sprintf("%s:%d", target, port)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// Handle interactive connection protocols that print greeting banners automatically (SSH, FTP, SMTP)
	if port == 21 || port == 22 || port == 25 || port == 110 || port == 143 {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil {
			line = strings.TrimSpace(line)
			return line, resolveServiceType(port, line)
		}
	}

	// Handle HTTP web servers (send active HTTP request probe)
	if port == 80 || port == 443 || port == 8080 || port == 8443 || port == 9000 {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		// Send raw HTTP request probe
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nUser-Agent: VulnSightAI-Verifier/1.0\r\n\r\n")
		
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					serverBanner := strings.TrimSpace(parts[1])
					return serverBanner, "http"
				}
			}
		}
	}

	// Handle Redis servers
	if port == 6379 {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(conn, "PING\r\n")
		
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "PONG") || strings.Contains(line, "NOAUTH") {
				return line, "redis"
			}
		}
	}

	return "", ""
}

func resolveServiceType(port int, banner string) string {
	bannerLower := strings.ToLower(banner)
	if strings.Contains(bannerLower, "ssh") {
		return "ssh"
	}
	if strings.Contains(bannerLower, "ftp") {
		return "ftp"
	}
	if strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "postfix") {
		return "smtp"
	}
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 25:
		return "smtp"
	}
	return "unknown"
}

// VerifyBannerConsensus performs side-by-side double verification validation checks.
func VerifyBannerConsensus(nmapService, nmapVersion, nativeBanner, nativeType string) (string, string) {
	nService := strings.ToLower(strings.TrimSpace(nmapService))
	nBanner := strings.ToLower(strings.TrimSpace(nativeBanner))
	
	if nativeBanner == "" {
		return nmapService, "NMAP_ONLY"
	}

	// 1. Check direct matches
	if strings.Contains(nBanner, nService) || (nativeType != "unknown" && nService == nativeType) {
		return nmapService, "MATCH"
	}

	// 2. Resolve missing nmap metadata
	if nService == "" || nService == "unknown" {
		return nativeType, "NATIVE_ONLY"
	}

	// 3. Flag active discrepancy warnings
	return nmapService, "DISCREPANCY"
}
