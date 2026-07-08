# 🛡️ VulnSightAI v2.0.0 (Military Grade)
> **Next-Generation Autonomous Reconnaissance, Threat Profiling, & AI-Driven Vulnerability Insights**

[![Version](https://img.shields.io/badge/Version-2.0.0-blueviolet?style=for-the-badge&logo=git)](https://github.com/pingsaketchoudhary/VulnSightAI)
[![Go Backend](https://img.shields.io/badge/Backend-Go%201.21-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![React Frontend](https://img.shields.io/badge/Frontend-Next.js%20React-black?style=for-the-badge&logo=nextdotjs)](https://nextjs.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)

---

## ☣️ System Overview

**VulnSightAI v2.0.0** is an enterprise-grade threat discovery and vulnerability correlation engine. Completely rewritten from the legacy Python/Streamlit codebase, the framework now harnesses a **high-concurrency Go Engine** and a **React/Next.js Matrix Dashboard** to deliver sub-second passive recon, native network banner mapping, secret leak checks, and automated AI security mitigations.

```
                  ┌──────────────────────────────┐
                  │      Target Identification   │
                  └──────────────┬───────────────┘
                                 ▼
         ┌───────────────────────┴───────────────────────┐
         │         Autonomous Go Scanning Engine         │
         └───────┬───────────────┬───────────────┬───────┘
                 │               │               │
                 ▼               ▼               ▼
         ┌───────────────┐┌───────────────┐┌───────────────┐
         │  TCP Banner   ││   Web Leak    ││ WAF & Network │
         │   Profiler    ││    Finder     ││  Diagnostics  │
         └───────┬───────┘└───────┬───────┘└───────┬───────┘
                 │               │               │
                 └───────────────┼───────────────┘
                                 ▼
         ┌───────────────────────┴───────────────────────┐
         │     CISA KEV & MITRE ATT&CK Threat Mapper     │
         └───────────────────────┬───────────────────────┘
                                 ▼
         ┌───────────────────────┴───────────────────────┐
         │      AI Contextual Classification Swarm       │
         └───────────────────────┬───────────────────────┘
                                 ▼
         ┌───────────────────────┴───────────────────────┐
         │   Matrix Dashboard (3000) & HTML Report Gen   │
         └───────────────────────────────────────────────┘
```

---

## ⚡ Key Features (v2.0.0 Premium Stack)

* **🚀 High-Concurrency Go Scanner**: Scans open ports, performs raw TCP handshakes, sends active protocol probes (HTTP/SMTP/SSH/Redis PINGs), and matches banners against Nmap signatures using a **Consensus Merger** to prevent discrepancy and service spoofing.
* **📡 CISA KEV & Zero-Day Threat Feed Aggregator**: Dynamically pulls and parses CISA's official **Known Exploited Vulnerabilities** catalog to flag vulnerabilities currently targeted by threat actors in the wild. Supports full offline fallback mode to eliminate DNS/HTTP leaks during covert operations.
* **🧠 Contextual Threat Classifier (AI Reviewer)**: Integrates with local LLMs (Ollama) to inspect findings and filter benign system services (YouTube, development workflows, database loops) from target attack surfaces.
* **🔥 Proprietary Web Leak Engine**: Passthroughs and searches for exposed secret variables (`.env`), source repositories (`.git/config`), SQL dumps, and compressed archives. Applies strict magic header validation to filter out wildcard page redirects.
* **📊 Real-time CVE & MITRE ATT&CK Correlation**: Automatically correlates identified software versions and leaks to CVSS scores, EPSS probabilities, and corresponding **MITRE ATT&CK Tactics** (Initial Access, Execution, Credential Access, lateral movement).
* **🎛️ Cyber-themed Matrix Dashboard**: Web UI displaying column tactics, active threat glows, interactive node graphs, real-time log streaming, and PDF/HTML exports.

---

## 🛠️ Installation & Engagement Guide

### Prereqs
* **Go** (v1.21 or higher)
* **Node.js** (v18 or higher)
* **Ollama** (for local AI reviews)
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull llama3:8b  # or mistral, phi3
  ```

### 1. Build and Start the Full-Stack Application
Execute the military-grade automated start script:
```bash
chmod +x start.sh
./start.sh
```
This automatically verifies Ollama, boots the Golang Backend Engine on port `8080`, and fires up the Next.js Dashboard on port `3000`.

### 2. Manual Setup (Optional)
**Backend:**
```bash
cd backend
go mod download
go build -o vulnsight_bin cmd/vulnsight/main.go
./vulnsight_bin
```
**Frontend:**
```bash
cd frontend
npm install
npm run build
npm run dev
```

---

## 💻 CLI Client Usage

The precompiled Go-based CLI client allows rapid, terminal-only assessments:

```bash
# Basic Scan
./vulnsight-cli --target example.com

# Comprehensive scan with custom threads and specific AI model
./vulnsight-cli --target example.com --threads 20 --ai-model llama3:8b --port-range 1-10000
```

### CLI Command Flags
| Flag | Description | Default |
| --- | --- | --- |
| `--target` | Target IP address or domain | `localhost` |
| `--threads` | Concurrent scan threads | `10` |
| `--ai-model` | Selected Ollama AI model | `llama3:8b` |
| `--port-range` | Custom port scan bounds | `1-1024` |

---

## 📦 Cross-Platform Installation Releases

We publish compiled CLI release packages for multiple platforms. You can download these binaries directly from our [GitHub Releases](https://github.com/pingsaketchoudhary/VulnSightAI/releases) section.

### 🐧 Debian / Ubuntu / Kali Linux (Installer Package)
Install using the native package manager:
```bash
sudo dpkg -i vulnsight-cli_2.0.0_amd64.deb
vulnsight-cli --target scanme.nmap.org
```

### 🍏 macOS (Darwin Client)
Download the macOS executable:
```bash
chmod +x vulnsight-cli-mac
./vulnsight-cli-mac --target scanme.nmap.org
```

### Windows CLI Client
Download `vulnsight-cli.exe` and execute it from PowerShell or Command Prompt:
```powershell
.\vulnsight-cli.exe --target scanme.nmap.org
```

---

## 📜 Disclaimer & Licensing

MIT License - Copyright (c) 2026 Saket Kumar Choudhary.

**WARNING**: This recon tool is strictly intended for educational exercises, ethical auditing, and authorized system assessments. Scanning targets without explicit permission is illegal. The author holds no liability for malicious actions or network abuse caused by this tool.