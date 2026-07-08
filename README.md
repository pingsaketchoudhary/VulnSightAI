# 🛡️ VulnSightAI v2.0.1 (Military Grade)
> **Next-Generation Autonomous Reconnaissance, Threat Profiling, & AI-Driven Vulnerability Insights**

[![Version](https://img.shields.io/badge/Version-2.0.1-blueviolet?style=for-the-badge&logo=git)](https://github.com/pingsaketchoudhary/VulnSightAI)
[![Go Backend](https://img.shields.io/badge/Backend-Go%201.21-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![React Frontend](https://img.shields.io/badge/Frontend-Next.js%20React-black?style=for-the-badge&logo=nextdotjs)](https://nextjs.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)

---

## ☣️ System Overview

**VulnSightAI v2.0.1** is an enterprise-grade threat discovery and vulnerability correlation engine. Completely rewritten from the legacy Python/Streamlit codebase, the framework now harnesses a **high-concurrency Go Engine** and a **React/Next.js Matrix Dashboard** to deliver sub-second passive recon, native network banner mapping, secret leak checks, and automated AI security mitigations.

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

## ⚡ Key Features (v2.0.1 Premium Stack)

* **🚀 High-Concurrency Go Scanner**: Scans open ports, performs raw TCP handshakes, sends active protocol probes (HTTP/SMTP/SSH/Redis PINGs), and matches banners against Nmap signatures using a **Consensus Merger** to prevent discrepancy and service spoofing.
* **📡 CISA KEV & Zero-Day Threat Feed Aggregator**: Dynamically pulls and parses CISA's official **Known Exploited Vulnerabilities** catalog to flag vulnerabilities currently targeted by threat actors in the wild. Supports full offline fallback mode to eliminate DNS/HTTP leaks during covert operations.
* **🧠 Contextual Threat Classifier (AI Reviewer)**: Integrates with local LLMs (Ollama) to inspect findings and filter benign system services (YouTube, development workflows, database loops) from target attack surfaces.
* **🔥 Proprietary Web Leak Engine**: Passthroughs and searches for exposed secret variables (`.env`), source repositories (`.git/config`), SQL dumps, and compressed archives. Applies strict magic header validation to filter out wildcard page redirects.
* **📊 Real-time CVE & MITRE ATT&CK Correlation**: Automatically correlates identified software versions and leaks to CVSS scores, EPSS probabilities, and corresponding **MITRE ATT&CK Tactics** (Initial Access, Execution, Credential Access, lateral movement).
* **🎛️ Cyber-themed Matrix Dashboard**: Web UI displaying column tactics, active threat glows, interactive node graphs, real-time log streaming, and PDF/HTML exports.

---

## 🛠️ Step-by-Step Installation Protocols

> [!IMPORTANT]
> **Single-Binary Engine Deployment:** Starting with **v2.0.1**, the React/Next.js frontend assets are fully compiled and embedded directly inside the Go backend server binary. You **no longer need Node.js, NPM, or `node_modules`** to run the graphical web dashboard in production! Running the Go server binary starts BOTH the backend API and the frontend dashboard on port `8080` out-of-the-box.

Please select your deployment platform below for detailed setup procedures.

---

### 🐧 Debian / Ubuntu / Kali Linux (CLI & GUI Setup)

#### Option A: Instant Production Launch (Recommended)
Deploy instantly without Go compilers, Node.js, or NPM. Only Ollama is required for local threat analysis:
```bash
# 1. Download and start local AI (Ollama)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve & 
ollama pull llama3:8b

# 2. Download precompiled VulnSightAI Server from Releases
wget https://github.com/pingsaketchoudhary/VulnSightAI/releases/download/v2.0.1/vulnsight-server
chmod +x vulnsight-server

# 3. Launch unified server (GUI & API live on port 8080)
./vulnsight-server
```
*Access the cyber matrix dashboard instantly at: `http://localhost:8080`*

#### Option B: Build from Source (Developer Setup)
If you want to compile files manually or modify the source:
```bash
# 1. Install prerequisites (Git, Go, Node.js, NPM, Ollama)
sudo apt update && sudo apt install git golang nodejs npm -y
curl -fsSL https://ollama.com/install.sh | sh
ollama serve & 
ollama pull llama3:8b

# 2. Clone repository & compile static frontend
git clone https://github.com/pingsaketchoudhary/VulnSightAI.git
cd VulnSightAI
cd frontend && npm install && npm run build
cd ..

# 3. Copy compiled frontend dist into Go embedded directory
mkdir -p backend/cmd/vulnsight/dist
cp -r frontend/out/* backend/cmd/vulnsight/dist/

# 4. Compile and launch unified backend server binary
cd backend
go build -o vulnsight-server cmd/vulnsight/main.go
./vulnsight-server
```

#### Option C: Native Debian CLI Client Installation
If you only need the terminal CLI client to scan targets without a GUI:
```bash
# Download and install via native package manager
wget https://github.com/pingsaketchoudhary/VulnSightAI/releases/download/v2.0.1/vulnsight-cli_2.0.1_amd64.deb
sudo dpkg -i vulnsight-cli_2.0.1_amd64.deb

# Execute scan
vulnsight-cli scan scanme.nmap.org
```

---

### 🍏 macOS / Darwin (CLI & GUI Setup)

#### Option A: Instant Production Launch (Recommended)
Deploy instantly without source code compilation, NPM, or Go compilers:
```bash
# 1. Install Ollama (using Homebrew or from ollama.com)
brew install ollama
ollama serve &
ollama pull llama3:8b

# 2. Download precompiled VulnSightAI Server
curl -L -O https://github.com/pingsaketchoudhary/VulnSightAI/releases/download/v2.0.1/vulnsight-server-mac
chmod +x vulnsight-server-mac

# 3. Run unified server (GUI & API live on port 8080)
./vulnsight-server-mac
```
*Access the cyber matrix board instantly at: `http://localhost:8080`*

#### Option B: Build from Source (Developer Setup)
```bash
# 1. Install dependencies
brew install git go node
brew install ollama
ollama serve &
ollama pull llama3:8b

# 2. Clone repository & compile static frontend
git clone https://github.com/pingsaketchoudhary/VulnSightAI.git
cd VulnSightAI
cd frontend && npm install && npm run build
cd ..

# 3. Copy compiled frontend dist into Go embedded directory
mkdir -p backend/cmd/vulnsight/dist
cp -r frontend/out/* backend/cmd/vulnsight/dist/

# 4. Compile and launch unified server
cd backend
go build -o vulnsight-server-mac cmd/vulnsight/main.go
./vulnsight-server-mac
```

---

### 🪟 Microsoft Windows (CLI & GUI Setup)

#### Option A: Instant Production Launch (Recommended)
Deploy instantly without source code, NPM, or Go compilers:
1. Download and run the **Ollama installer** from [ollama.com/download/windows](https://ollama.com/download/windows). Once active, pull the model in PowerShell:
   ```powershell
   ollama pull llama3:8b
   ```
2. Download `vulnsight-server.exe` from the [GitHub Releases](https://github.com/pingsaketchoudhary/VulnSightAI/releases/tag/v2.0.1) page.
3. Open PowerShell and launch the server:
   ```powershell
   .\vulnsight-server.exe
   ```
*Access the cyber matrix board instantly at: `http://localhost:8080`*

#### Option B: Build from Source (Developer Setup)
1. Download and install standard tools:
   * **Git**: [git-scm.com/download/win](https://git-scm.com/download/win)
   * **Go**: [go.dev/dl/](https://go.dev/dl/)
   * **Node.js**: [nodejs.org/en/download/](https://nodejs.org/en/download/)
   * **Ollama**: [ollama.com/download/windows](https://ollama.com/download/windows)
2. Open PowerShell and build the codebase:
   ```powershell
   # Clone & install frontend libraries
   git clone https://github.com/pingsaketchoudhary/VulnSightAI.git
   cd VulnSightAI
   cd frontend
   npm install
   npm run build
   cd ..

   # Compile React dist to Go embedded path
   mkdir backend\cmd\vulnsight\dist
   xcopy /E /I frontend\out\* backend\cmd\vulnsight\dist\

   # Build unified server binary
   cd backend
   go build -o vulnsight-server.exe cmd/vulnsight/main.go
   .\vulnsight-server.exe
   ```

---

## 💻 CLI Client Usage Reference

```bash
# Basic Scan on localhost
./vulnsight-cli scan localhost

# Comprehensive scan with custom model, custom ports, and proxy configuration
./vulnsight-cli --model llama3:8b scan --ports 80,443,8080 --speed T4 --depth deep example.com

# List past scan history
./vulnsight-cli list

# Retrieve and inspect findings for scan ID 5
./vulnsight-cli show 5

# Download HTML report for scan ID 5
./vulnsight-cli report 5 audit_report.html
```

### CLI Command Reference
* **Global Flags:**
  - `--server <url>`: VulnSightAI engine server URL (default: `http://localhost:8080`)
  - `--api-key <key>`: Optional API key token header for server auth
  - `--model <name>`: Ollama model name target for AI reviews (e.g. `llama3:8b`)

* **Commands:**
  - **`scan [flags] <target>`**: Triggers a live vulnerability scan.
    - `--ports <range>`: Ports to scan (common, all, or custom ports like 80,443) [default: `common`]
    - `--speed <level>`: Nmap speed T1 (slow) to T5 (insane) [default: `T3`]
    - `--depth <mode>`: Subdomain brute-forcing depth (fast, deep) [default: `fast`]
    - `--template <name>`: Custom Nuclei template file to execute
    - `--proxy <url>`: SOCKS5/HTTP proxy tunnel (e.g. `socks5://127.0.0.1:9050`)
    - `--user-agent <ua>`: Custom HTTP User-Agent header string
    - `--rate-limit <rps>`: Request rate limit (RPS) [default: `0` / unlimited]
  - **`list`**: Retrieves past scan archives.
  - **`report <scan_id> [output_file]`**: Downloads compiled HTML scan report sheets.
  - **`show <scan_id>`**: Outputs formatted scan findings in the terminal.

---

## 📦 Cross-Platform Installation Releases

We publish compiled CLI release packages for multiple platforms. You can download these binaries directly from our [GitHub Releases](https://github.com/pingsaketchoudhary/VulnSightAI/releases) section.

### 🐧 Debian / Ubuntu / Kali Linux (Installer Package)
Install using the native package manager:
```bash
sudo dpkg -i vulnsight-cli_2.0.1_amd64.deb
vulnsight-cli scan scanme.nmap.org
```

### 🍏 macOS (Darwin Client)
Download the macOS executable:
```bash
chmod +x vulnsight-cli-mac
./vulnsight-cli-mac scan scanme.nmap.org
```

### Windows CLI Client
Download `vulnsight-cli.exe` and execute it from PowerShell or Command Prompt:
```powershell
.\vulnsight-cli.exe scan scanme.nmap.org
```

---

## 📜 Disclaimer & Licensing

MIT License - Copyright (c) 2026 Saket Kumar Choudhary.

**WARNING**: This recon tool is strictly intended for educational exercises, ethical auditing, and authorized system assessments. Scanning targets without explicit permission is illegal. The author holds no liability for malicious actions or network abuse caused by this tool.