package setup

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Tool details structure
type ToolRelease struct {
	Name    string
	Version string
	Url     string
}

// GetToolBinDir returns the absolute path to ~/.vulnsight/bin
func GetToolBinDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(homeDir, ".vulnsight", "bin")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

// ResolveToolPath checks local path then falls back to global exec.LookPath
func ResolveToolPath(toolName string) (string, error) {
	binDir, err := GetToolBinDir()
	if err == nil {
		localPath := filepath.Join(binDir, toolName)
		if runtime.GOOS == "windows" {
			localPath += ".exe"
		}
		if _, err := os.Stat(localPath); err == nil {
			return localPath, nil
		}
	}
	return exec.LookPath(toolName)
}

// IsToolInstalled checks if a tool is active locally or globally
func IsToolInstalled(toolName string) bool {
	_, err := ResolveToolPath(toolName)
	return err == nil
}

// GetDownloadURL resolves standard release URL depending on target platform
func GetDownloadURL(tool, version string) string {
	osName := runtime.GOOS
	archName := runtime.GOARCH

	// Map GOOS to ProjectDiscovery naming conventions
	switch osName {
	case "darwin":
		osName = "macOS"
	case "windows":
		osName = "windows"
	case "linux":
		osName = "linux"
	}

	// Map GOARCH
	switch archName {
	case "amd64":
		archName = "amd64"
	case "arm64":
		archName = "arm64"
	case "386":
		archName = "386"
	}

	if tool == "nuclei" {
		return fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/download/v%s/nuclei_%s_%s_%s.zip", version, version, osName, archName)
	} else if tool == "subfinder" {
		return fmt.Sprintf("https://github.com/projectdiscovery/subfinder/releases/download/v%s/subfinder_%s_%s_%s.zip", version, version, osName, archName)
	} else if tool == "katana" {
		return fmt.Sprintf("https://github.com/projectdiscovery/katana/releases/download/v%s/katana_%s_%s_%s.zip", version, version, osName, archName)
	}
	return ""
}

// BootstrapTool downloads, extracts, and permissions a zip release to the local bin
func BootstrapTool(tool, version string) error {
	binDir, err := GetToolBinDir()
	if err != nil {
		return fmt.Errorf("failed to get local bin path: %v", err)
	}

	url := GetDownloadURL(tool, version)
	if url == "" {
		return fmt.Errorf("unsupported platform OS/Arch configuration")
	}

	// 1. Download zip file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github release returned status %d", resp.StatusCode)
	}

	tmpZip, err := os.CreateTemp("", "vulnsight_zip_*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temporary archive file: %v", err)
	}
	defer os.Remove(tmpZip.Name())
	defer tmpZip.Close()

	_, err = io.Copy(tmpZip, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write archive content: %v", err)
	}

	// 2. Unzip and extract the binary executable
	r, err := zip.OpenReader(tmpZip.Name())
	if err != nil {
		return fmt.Errorf("failed to read zip archive: %v", err)
	}
	defer r.Close()

	binaryName := tool
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	var extracted bool
	for _, f := range r.File {
		// Matching root level binary file in archive
		if f.Name == binaryName || strings.HasSuffix(f.Name, "/"+binaryName) {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("failed to open file inside zip: %v", err)
			}

			destPath := filepath.Join(binDir, binaryName)
			// Remove older binary if present
			os.Remove(destPath)

			destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return fmt.Errorf("failed to write binary file to local path: %v", err)
			}

			_, err = io.Copy(destFile, rc)
			destFile.Close()
			rc.Close()

			if err != nil {
				return fmt.Errorf("failed to write binary stream: %v", err)
			}

			extracted = true
			break
		}
	}

	if !extracted {
		return fmt.Errorf("executable binary file '%s' was not found inside the downloaded release archive", binaryName)
	}

	return nil
}
