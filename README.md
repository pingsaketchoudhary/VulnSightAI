VulnSightAI: An AI-Powered Reconnaissance Toolkit 🛡️🤖
VulnSightAI is an open-source, command-line framework designed for ethical hackers, bug bounty hunters, and security professionals. It automates the reconnaissance process and leverages Artificial Intelligence to suggest potential vulnerabilities (CVEs), accelerating security analysis.

✨ Key Features
Subdomain Enumeration: Leverages subfinder to discover subdomains.

Port Scanning: Utilizes nmap to identify open ports and running services.

Technology Detection: Employs whatweb to recognize the technology stack on the web server (e.g., Apache, PHP, WordPress).

🧠 AI-Powered CVE Suggestions: Uses the Google Gemini AI to suggest potential vulnerabilities based on the detected technologies.

📄 Professional Reporting: Exports all findings into a clean and professional HTML and PDF report.

Zero Cost: Built entirely on free and open-source tools.

🚀 Demo
(You can add a screenshot or a short GIF of the tool in action here. A good visual is highly impactful.)

🛠️ Installation Guide (Kali Linux)
This tool has been tested on Kali Linux. Follow the steps below to set it up.

1. Clone the Repository:

git clone https://github.com/pingsaketchoudhary/VulnSightAI.git
cd VulnSightAI

2. Install Required Tools:

# Install Go (for Subfinder)
sudo apt update && sudo apt install golang-go -y

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Set the path for Subfinder
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install wkhtmltopdf (for PDF reports)
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
sudo dpkg -i wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
sudo apt-get install -f -y

3. Set Up Python Environment and Dependencies:

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

4. Set Up API Key:

Generate a free API key from Google AI Studio.

Create a file named config.json in the project's root folder.

Add the following content to the file and paste your key:

{
  "GEMINI_API_KEY": "PASTE_YOUR_API_KEY_HERE"
}

Important: Do not forget to add config.json to your .gitignore file to keep your API key private.

usage Usage
Run the tool from the project's root directory.

Basic Scan:

python3 src/main_cli.py --target example.com

Save JSON Output:

python3 src/main_cli.py --target example.com --output-json output/results.json

Generate HTML and PDF Reports:

python3 src/main_cli.py --target example.com --html output/report.html --pdf output/report.pdf

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
