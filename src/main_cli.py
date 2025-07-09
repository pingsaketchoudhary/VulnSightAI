# src/main_cli.py

import argparse
import json
import os # Naya import, directory operations ke liye
from recon_engine import run_all_scans
from report_generator import generate_html_report, save_pdf_report

def ensure_dir(file_path):
    """
    Sunishchit karta hai ki file save karne ke liye directory maujood hai.
    Agar directory nahi hai, to use bana deta hai.
    """
    # file_path se directory ka naam nikalta hai (e.g., 'output/report.pdf' -> 'output')
    directory = os.path.dirname(file_path)
    
    # Check karta hai ki directory ka naam hai aur woh maujood nahi hai
    if directory and not os.path.exists(directory):
        print(f"[+] Directory '{directory}' maujood nahi hai, banayi ja rahi hai...")
        os.makedirs(directory)

def main():
    """
    Tool ke liye main function, jo user input ko handle karta hai.
    """
    parser = argparse.ArgumentParser(description="VulnSightAI - An AI-Powered Reconnaissance Toolkit")
    
    parser.add_argument("-t", "--target", required=True, help="Target domain jise scan karna hai (e.g., example.com)")
    parser.add_argument("-oJ", "--output-json", help="Scan ke result ko save karne ke liye JSON file ka naam (e.g., output/result.json)")
    
    parser.add_argument("--html", help="HTML report generate karein aur is file path par save karein (e.g., output/report.html)")
    parser.add_argument("--pdf", help="PDF report generate karein aur is file path par save karein (e.g., output/report.pdf)")
    
    args = parser.parse_args()
    target_domain = args.target
    
    scan_results = run_all_scans(target_domain)
    
    print("\n" + "="*20 + " SCAN COMPLETE " + "="*20)
    print(json.dumps(scan_results, indent=4))
    print("="*55)
    
    if args.output_json:
        ensure_dir(args.output_json) # UPDATE: Directory check karein
        print(f"\n[+] Scan ke nateeje ko '{args.output_json}' file me save kiya ja raha hai...")
        try:
            with open(args.output_json, 'w') as f:
                json.dump(scan_results, f, indent=4)
            print(f"[+] Safaltapoorvak '{args.output_json}' me save kiya gaya.")
        except Exception as e:
            print(f"[!] ERROR: JSON file save karne me truti hui: {e}")

    if args.html or args.pdf:
        html_report = generate_html_report(scan_results)
        
        if args.html:
            ensure_dir(args.html) # UPDATE: Directory check karein
            print(f"\n[+] HTML report ko '{args.html}' me save kiya ja raha hai...")
            try:
                with open(args.html, 'w') as f:
                    f.write(html_report)
                print(f"[+] Safaltapoorvak '{args.html}' me save kiya gaya.")
            except Exception as e:
                print(f"[!] ERROR: HTML file save karne me truti hui: {e}")

        if args.pdf:
            ensure_dir(args.pdf) # UPDATE: Directory check karein
            print(f"\n[+] PDF report ko '{args.pdf}' me save kiya ja raha hai...")
            save_pdf_report(html_report, args.pdf)

if __name__ == "__main__":
    main()
