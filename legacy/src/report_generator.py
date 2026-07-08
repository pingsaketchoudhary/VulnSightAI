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
    Scan data se HTML report banata hai, jisme Nuclei findings bhi honge.
    """
    print_status("HTML report generate ki ja rahi hai...")
    
    target = scan_data.get('target', 'N/A')
    subdomains = scan_data.get('subdomains', [])
    nmap_scan_raw = scan_data.get('nmap_scan', 'Scan nahi hua.')
    technologies = scan_data.get('technologies', [])
    ai_suggestions_raw = scan_data.get('ai_suggestions', 'Koi suggestion nahi mila.')
    nuclei_findings = scan_data.get('nuclei_findings', []) 
    
    nmap_scan_html = nmap_scan_raw.replace('\n', '<br>')
    ai_suggestions_html = ai_suggestions_raw.replace('\n', '<br>')

    tech_html = "".join([f"<li><strong>{t.get('name', 'N/A')}:</strong> {t.get('version', '')}</li>" for t in technologies]) if technologies else "<li>No technologies detected.</li>"
    subdomain_html = "".join([f"<li>{s}</li>" for s in subdomains]) if subdomains else "<li>No subdomains found.</li>"

    
    nuclei_html = ""
    if nuclei_findings:
        nuclei_html += """
        <table class="styled-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Name</th>
                    <th>Matched At</th>
                </tr>
            </thead>
            <tbody>
        """
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sorted_findings = sorted(nuclei_findings, key=lambda x: severity_order.get(x.get('info', {}).get('severity', 'info'), 0), reverse=True)

        for finding in sorted_findings:
            info = finding.get('info', {})
            severity = info.get('severity', 'info').capitalize()
            name = info.get('name', 'N/A')
            matched_at = finding.get('matched-at', 'N/A')
            nuclei_html += f"""
            <tr class="severity-{severity.lower()}">
                <td>{severity}</td>
                <td>{name}</td>
                <td>{matched_at}</td>
            </tr>
            """
        nuclei_html += "</tbody></table>"
    else:
        nuclei_html = "<p>No vulnerabilities confirmed by Nuclei.</p>"

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
            .section {{ margin-top: 20px; }}
            .section h2 {{ color: #4a90e2; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
            .nuclei-section h2 {{ color: #c9302c; }}
            pre {{ background-color: #eee; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}
            .styled-table {{ border-collapse: collapse; margin: 25px 0; font-size: 0.9em; width: 100%; box-shadow: 0 0 20px rgba(0, 0, 0, 0.15); }}
            .styled-table thead tr {{ background-color: #009879; color: #ffffff; text-align: left; }}
            .styled-table th, .styled-table td {{ padding: 12px 15px; }}
            .styled-table tbody tr {{ border-bottom: 1px solid #dddddd; }}
            .styled-table tbody tr:nth-of-type(even) {{ background-color: #f3f3f3; }}
            .styled-table tbody tr:last-of-type {{ border-bottom: 2px solid #009879; }}
            .severity-critical {{ background-color: #d9534f !important; color: white; }}
            .severity-high {{ background-color: #f0ad4e !important; color: white; }}
            .severity-medium {{ background-color: #5bc0de !important; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>VulnSightAI Scan Report</h1><p>Target: <strong>{target}</strong></p></div>
            
            <div class="section nuclei-section">
                <h2>Confirmed Vulnerabilities (Nuclei)</h2>
                {nuclei_html}
            </div>

            <div class="section"><h2>AI-Powered CVE Suggestions</h2><pre>{ai_suggestions_html}</pre></div>
            <div class="section"><h2>Subdomain Enumeration</h2><ul>{subdomain_html}</ul></div>
            <div class="section"><h2>Nmap Port Scan Results</h2><pre>{nmap_scan_html}</pre></div>
            <div class="section"><h2>Technology Stack</h2><ul>{tech_html}</ul></div>
        </div>
    </body>
    </html>
    """
    return html_content

def save_pdf_report(html_content, output_file):
    try:
        path_wkhtmltopdf = shutil.which('wkhtmltopdf') or '/usr/local/bin/wkhtmltopdf'
        config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        pdfkit.from_string(html_content, output_file, configuration=config)
        return True
    except Exception as e:
        print_error(f"PDF generate karne me truti hui: {e}")
        return False
