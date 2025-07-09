# src/recon_engine.py

import subprocess
import json
import sys
import shutil # Naya import, tools ka path dhoondhne ke liye
from ai_suggester import get_cve_suggestions # Naya import

def print_status(message):
    """Console par status message print karta hai."""
    print(f"[+] {message}")

def print_error(message):
    """Console par error message print karta hai."""
    print(f"[!] ERROR: {message}", file=sys.stderr)

def find_tool_path(tool_name):
    """
    Ek tool ka poora path system me dhoondhta hai.
    Yeh 'which' command ki tarah kaam karta hai.
    """
    path = shutil.which(tool_name)
    if path is None:
        print_error(f"Tool '{tool_name}' nahi mila. Kripya sunishchit karein ki yeh install hai aur aapke system ke PATH me hai.")
    return path

def run_subfinder(target_domain):
    """Subfinder tool chala kar subdomains khojta hai."""
    subfinder_path = find_tool_path("subfinder")
    if not subfinder_path:
        return []

    print_status(f"'{target_domain}' ke liye subdomains khoje ja rahe hain...")
    command = [subfinder_path, "-d", target_domain, "-silent"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        subdomains = result.stdout.strip().split('\n')
        valid_subdomains = [s for s in subdomains if s]
        print_status(f"Kul {len(valid_subdomains)} subdomains mile.")
        return valid_subdomains
    except Exception as e:
        print_error(f"subfinder me anapekshit truti: {e}")
        return []

def run_nmap(target):
    """Nmap chala kar open ports aur services ka pata lagata hai."""
    nmap_path = find_tool_path("nmap")
    if not nmap_path:
        return "Error: nmap nahi mila."

    print_status(f"'{target}' par Nmap scan shuru ho raha hai...")
    command = [nmap_path, "-F", "-sV", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print_status("Nmap scan poora hua.")
        return result.stdout
    except Exception as e:
        print_error(f"nmap me anapekshit truti: {e}")
        return f"Error: {e}"

def run_whatweb(target):
    """WhatWeb chala kar technology stack ka pata lagata hai."""
    whatweb_path = find_tool_path("whatweb")
    if not whatweb_path:
        return []
        
    print_status(f"'{target}' par technology stack ki jaanch ho rahi hai...")
    command = [whatweb_path, target, "--log-json=-"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print_status("Technology ki jaanch poori hui.")
        
        # UPDATE: JSON ko parse karne ka naya, behtar tareeka.
        # Yeh whatweb ke output ko line-by-line padhta hai.
        parsed_results = []
        for line in result.stdout.strip().split('\n'):
            try:
                # Har line ko JSON me badalne ki koshish karta hai
                parsed_json = json.loads(line)
                parsed_results.append(parsed_json)
            except json.JSONDecodeError:
                # Agar koi line valid JSON nahi hai (jaise koi warning), to use ignore kar deta hai.
                pass 
        return parsed_results

    except subprocess.CalledProcessError as e:
        print_error(f"whatweb me error aaya, lekin kuch output mila: {e.stdout}")
        return []
    except Exception as e:
        print_error(f"whatweb me anapekshit truti: {e}")
        return []

def run_all_scans(target_domain):
    """Saare scans ko chalata hai aur AI suggestions bhi leta hai."""
    print_status(f"'{target_domain}' ke liye poora scan shuru kiya ja raha hai...")
    recon_data = {
        "target": target_domain,
        "subdomains": [],
        "nmap_scan": "",
        "technologies": [],
        "ai_suggestions": "" # AI suggestions ke liye nayi field
    }
    recon_data["subdomains"] = run_subfinder(target_domain)
    recon_data["nmap_scan"] = run_nmap(target_domain)
    recon_data["technologies"] = run_whatweb(target_domain)
    recon_data["ai_suggestions"] = get_cve_suggestions(recon_data["technologies"])
    print_status("Poora scan safaltapoorvak poora hua.")
    return recon_data

if __name__ == '__main__':
    test_target = "scanme.nmap.org" 
    all_data = run_all_scans(test_target)
    print("\n--- Scan Ke Nateeje ---")
    print(json.dumps(all_data, indent=4))
