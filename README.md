VulnSightAI: An AI-Powered Vulnerability Assessment Dashboard 

VulnSightAI is a comprehensive, open-source framework that automates the initial stages of a penetration test. It integrates reconnaissance, AI-driven analysis, and real vulnerability scanning into a single, easy-to-use tool with both a CLI and an interactive Web Dashboard.

✨ Key Features

Interactive Web Dashboard: A user-friendly interface built with Streamlit to run scans and visualize results.

Persistent Database: Uses SQLite to save all scan results, providing a complete history of past assessments.

Real Vulnerability Scanning: Leverages the power of Nuclei to run thousands of templates and confirm real-world vulnerabilities.

Automated Reconnaissance: Discovers subdomains (subfinder), scans for open ports (nmap), and identifies web technologies (whatweb).

🧠 AI-Powered CVE Suggestions: Uses the Google Gemini AI to suggest potential CVEs based on the detected technologies for further research.

📄 Professional Reporting: Exports all findings into clean HTML and PDF reports, downloadable directly from the web dashboard.

🚀 Demo

Web Dashboard Interface:
(A screenshot of your web app showing the Nuclei findings and scan history would be perfect here)

🛠️ Installation Guide (Kali Linux)
This tool is designed for Debian-based systems like Kali Linux.

1. Clone the Repository:

git clone https://github.com/pingsaketchoudhary/VulnSightAI.git
cd VulnSightAI

2. Install Required Tools:

# Install Go, Nuclei, Subfinder, and other dependencies
sudo apt update && sudo apt install golang-go -y
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
nuclei -update-templates

# Install wkhtmltopdf for PDF reports
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
sudo dpkg -i wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
sudo apt-get install -f -y

3. Set Up Python Environment:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

4. Set Up API Key:

Generate a free API key from Google AI Studio.

Create a file named config.json in the project's root folder.

Add the following content and paste your key:

{
  "GEMINI_API_KEY": "PASTE_YOUR_API_KEY_HERE"
}

usage Usage

Running the Web Dashboard (Recommended)
streamlit run web/app.py

Open your browser and navigate to the local URL provided by Streamlit.

Running the CLI Tool
# Basic scan with PDF report
python3 src/main_cli.py --target example.com --pdf output/report.pdf


📂 Project Structure
/VulnSightAI
│
├── /src
│   ├── main_cli.py
│   ├── recon_engine.py
│   ├── ai_suggester.py
│   └── report_generator.py
│
├── /output/
│   └── .gitkeep
│
├── config.json
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore

📜 License
This project is licensed under the MIT License.

⚠️ Disclaimer
This tool is intended for educational purposes and ethical testing only. Use it only on systems for which you have explicit permission. The developer is not responsible for any unauthorized activities.