# src/recon_engine.py

import subprocess
import json
import sys
import shutil
import time
import os
from .ai_suggester import get_cve_suggestions
from .database import save_scan_result

def print_status(message):
    print(f"[+] {message}")

def print_error(message):
    print(f"[!] ERROR: {message}", file=sys.stderr)

def find_tool_path(tool_name):
    path = shutil.which(tool_name)
    if path is None:
        print_error(f"Tool '{tool_name}' nahi mila.")
    return path



def run_subfinder(target_domain):
    subfinder_path = find_tool_path("subfinder")
    if not subfinder_path: return []
    print_status(f"'{target_domain}' ke liye subdomains khoje ja rahe hain...")
    command = [subfinder_path, "-d", target_domain, "-silent"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        subdomains = result.stdout.strip().split('\n')
        return [s for s in subdomains if s]
    except Exception as e:
        print_error(f"subfinder me anapekshit truti: {e}")
        return []

def run_nmap(target):
    nmap_path = find_tool_path("nmap")
    if not nmap_path: return "Error: nmap nahi mila."
    print_status(f"'{target}' par Nmap scan shuru ho raha hai...")
    command = [nmap_path, "-F", "-sV", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        print_error(f"nmap me anapekshit truti: {e}")
        return f"Error: {e}"

def run_whatweb(target):
    whatweb_path = find_tool_path("whatweb")
    if not whatweb_path: return []
    print_status(f"'{target}' par technology stack ki jaanch ho rahi hai...")
    command = [whatweb_path, target, "--log-json=-"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        parsed_results = []
        for line in result.stdout.strip().split('\n'):
            try:
                parsed_results.append(json.loads(line))
            except json.JSONDecodeError: pass
        return parsed_results
    except Exception as e:
        print_error(f"whatweb me anapekshit truti: {e}")
        return []


def run_nuclei(target):
    """
    Nuclei chala kar real vulnerabilities ka pata lagata hai.
    """
    nuclei_path = find_tool_path("nuclei")
    if not nuclei_path:
        return []

    print_status(f"'{target}' par Nuclei vulnerability scan shuru ho raha hai...")
    
    
    output_file = f"/tmp/{target}_nuclei.json"
    
    # Command: -u for target, -jsonl for json line output, -o for output file
    command = [nuclei_path, "-u", target, "-jsonl", "-o", output_file]
    
    try:
        
        subprocess.run(command, capture_output=True, text=True)
        
        
        if not os.path.exists(output_file):
            print_status("Nuclei scan poora hua, koi vulnerability nahi mili.")
            return []
            
        
        with open(output_file, 'r') as f:
            findings = [json.loads(line) for line in f]
        
        
        os.remove(output_file)
        
        print_status(f"Nuclei scan poora hua, {len(findings)} potential findings mile.")
        return findings
    except Exception as e:
        print_error(f"Nuclei me anapekshit truti: {e}")
        return []


def run_all_scans(target_domain):
    """
    Saare scans ko chalata hai aur result ko database me save karta hai.
    """
    print_status(f"'{target_domain}' ke liye poora scan shuru kiya ja raha hai...")
    recon_data = {
        "target": target_domain,
        "subdomains": [],
        "nmap_scan": "",
        "technologies": [],
        "ai_suggestions": "",
        "nuclei_findings": []
    }
    
    recon_data["subdomains"] = run_subfinder(target_domain)
    recon_data["nmap_scan"] = run_nmap(target_domain)
    recon_data["technologies"] = run_whatweb(target_domain)
    recon_data["ai_suggestions"] = get_cve_suggestions(recon_data["technologies"])
    recon_data["nuclei_findings"] = run_nuclei(target_domain)
    

    save_scan_result(recon_data)
    
    print_status("Poora scan safaltapoorvak poora hua.")
    return recon_data
