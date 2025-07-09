# src/report_generator.py

import pdfkit
import datetime
import shutil

def print_status(message):
    print(f"[+] {message}")

def print_error(message):
    print(f"[!] ERROR: {message}")

def generate_html_report(scan_data):
    """
    Scan data se ek HTML report string generate karta hai, jisme AI suggestions bhi honge.
    """
    print_status("HTML report generate ki ja rahi hai...")
    
    target = scan_data.get('target', 'N/A')
    subdomains = scan_data.get('subdomains', [])
    nmap_scan_raw = scan_data.get('nmap_scan', 'Scan nahi hua.')
    technologies = scan_data.get('technologies', [])
    ai_suggestions_raw = scan_data.get('ai_suggestions', 'Koi suggestion nahi mila.') # AI data
    
    nmap_scan_html = nmap_scan_raw.replace('\n', '<br>')
    ai_suggestions_html = ai_suggestions_raw.replace('\n', '<br>') # AI data ko HTML format me

    tech_html_parts = []
    if technologies:
        for tech_info in technologies:
            for plugin, details in tech_info.get('plugins', {}).items():
                version = ', '.join(details.get('version', []))
                tech_html_parts.append(f"<li><strong>{plugin}:</strong> {version}</li>")
    tech_html = "".join(tech_html_parts) if tech_html_parts else "<li>Koi technology nahi mili.</li>"

    subdomain_html_parts = [f"<li>{s}</li>" for s in subdomains]
    subdomain_html = "".join(subdomain_html_parts) if subdomain_html_parts else "<li>Koi subdomain nahi mila.</li>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>VulnSightAI Scan Report - {target}</title>
        <style>
            body {{ font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }}
            .container {{ max-width: 800px; margin: 20px auto; background: #fff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 20px; }}
            .header {{ text-align: center; border-bottom: 2px solid #d9534f; padding-bottom: 10px; }}
            .header h1 {{ color: #d9534f; margin: 0; }}
            .header p {{ margin: 5px 0 0; color: #777; }}
            .section {{ margin-top: 20px; }}
            .section h2 {{ color: #4a90e2; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
            .ai-section h2 {{ color: #d9534f; }} /* AI section ka alag color */
            pre {{ background-color: #eee; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; }}
            ul {{ list-style-type: square; padding-left: 20px; }}
            li {{ margin-bottom: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>VulnSightAI Scan Report</h1>
                <p>Target: <strong>{target}</strong></p>
                <p>Scan Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>

            <!-- AI Suggestions Section -->
            <div class="section ai-section">
                <h2>AI-Powered CVE Suggestions</h2>
                <pre>{ai_suggestions_html}</pre>
            </div>

            <div class="section">
                <h2>Subdomain Enumeration</h2>
                <ul>{subdomain_html}</ul>
            </div>

            <div class="section">
                <h2>Nmap Port Scan Results</h2>
                <pre>{nmap_scan_html}</pre>
            </div>

            <div class="section">
                <h2>Technology Stack</h2>
                <ul>{tech_html}</ul>
            </div>
        </div>
    </body>
    </html>
    """
    print_status("HTML report safaltapoorvak generate hui.")
    return html_content

def save_pdf_report(html_content, output_file):
    try:
        print_status(f"PDF report ko '{output_file}' me save kiya ja raha hai...")
        path_wkhtmltopdf = shutil.which('wkhtmltopdf') or '/usr/local/bin/wkhtmltopdf'
        config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        pdfkit.from_string(html_content, output_file, configuration=config)
        print_status(f"PDF report safaltapoorvak '{output_file}' me save hui.")
        return True
    except Exception as e:
        print_error(f"PDF generate karne me truti hui: {e}")
        return False
