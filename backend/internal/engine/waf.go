package engine

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// DetectWAF analyzes DNS records and HTTP headers to detect active WAF/CDN guards.
// Returns: wafName (e.g., "Cloudflare"), details (e.g., "Matched Server: cloudflare")
func DetectWAF(target string) (string, string) {
	// 1. DNS CNAME analysis
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, target)
	if err == nil && cname != "" {
		cnameLower := strings.ToLower(cname)
		if strings.Contains(cnameLower, "cloudflare") {
			return "Cloudflare", "DNS CNAME matched: " + cname
		}
		if strings.Contains(cnameLower, "cloudfront") {
			return "AWS Cloudfront", "DNS CNAME matched: " + cname
		}
		if strings.Contains(cnameLower, "akamai") {
			return "Akamai", "DNS CNAME matched: " + cname
		}
		if strings.Contains(cnameLower, "sucuri") {
			return "Sucuri", "DNS CNAME matched: " + cname
		}
		if strings.Contains(cnameLower, "fastly") {
			return "Fastly", "DNS CNAME matched: " + cname
		}
		if strings.Contains(cnameLower, "imperva") || strings.Contains(cnameLower, "incapsula") {
			return "Imperva", "DNS CNAME matched: " + cname
		}
	}

	// 2. HTTP response headers matching
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects to capture initial WAF header
		},
	}

	protocols := []string{"https://", "http://"}
	for _, proto := range protocols {
		req, err := http.NewRequest("GET", proto+target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Match signature headers
		if resp.Header.Get("CF-RAY") != "" || strings.ToLower(resp.Header.Get("Server")) == "cloudflare" {
			return "Cloudflare", "HTTP Headers matched (CF-RAY / Server header)"
		}
		if resp.Header.Get("x-amz-cf-id") != "" || resp.Header.Get("X-Amz-Cf-Pop") != "" {
			return "AWS Cloudfront", "HTTP Headers matched (x-amz-cf-id)"
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "akamaighost") {
			return "Akamai", "HTTP Headers matched (AkamaiGHost)"
		}
		if resp.Header.Get("x-sucuri-id") != "" || resp.Header.Get("X-Sucuri-Cache") != "" {
			return "Sucuri", "HTTP Headers matched (x-sucuri-id)"
		}
		if resp.Header.Get("x-fastly-request-id") != "" || strings.ToLower(resp.Header.Get("Server")) == "fastly" {
			return "Fastly", "HTTP Headers matched (Fastly)"
		}
		if resp.Header.Get("X-Iinfo") != "" || strings.Contains(strings.ToLower(resp.Header.Get("Server")), "imperva") {
			return "Imperva", "HTTP Headers matched (X-Iinfo / Server)"
		}
	}

	return "", ""
}
