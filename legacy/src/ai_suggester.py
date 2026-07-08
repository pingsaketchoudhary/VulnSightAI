# src/ai_suggester.py

import os
import requests
import json
import time 

def print_status(message):
    """Console par status message print karta hai."""
    print(f"[+] {message}")

def print_error(message):
    """Console par error message print karta hai."""
    print(f"[!] ERROR: {message}")

def get_api_key():
    """
    config.json file se API key padhta hai.
    """
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
        with open(config_path) as config_file:
            config = json.load(config_file)
            return config.get("GEMINI_API_KEY")
    except FileNotFoundError:
        print_error("Configuration file 'config.json' nahi mili.")
        return None
    except json.JSONDecodeError:
        print_error("'config.json' file ka format sahi nahi hai.")
        return None

def get_cve_suggestions(technologies):
    """
    Detected technologies ke basis par Google Gemini AI se CVE suggestions leta hai.
    """
    api_key = get_api_key()
    if not api_key:
        return "API Key not configured properly in config.json."

    print_status("Google Gemini AI se CVE suggestions maange ja rahe hain...")

    tech_list = []
    if technologies:
        for tech_info in technologies:
            for plugin, details in tech_info.get('plugins', {}).items():
                version = details.get('version', [])
                if version:
                    tech_list.append(f"{plugin} {', '.join(version)}")
                else:
                    tech_list.append(plugin)
    
    if not tech_list:
        print_status("AI analysis ke liye koi technology nahi mili.")
        return "AI analysis ke liye koi technology nahi mili."

    prompt = (
        "You are a cybersecurity expert. Based on the following technologies, "
        "list the top 3-5 most critical potential CVEs (Common Vulnerabilities and Exposures). "
        "For each CVE, provide the CVE ID, a brief description, and the severity (e.g., Critical, High, Medium). "
        "Format the output as a simple, human-readable text. "
        f"Technologies detected: {', '.join(tech_list)}"
    )

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=60)
            
            
            if 500 <= response.status_code < 600:
                print_error(f"Server error (Status {response.status_code}). {attempt + 1}/{max_retries} koshish. 5 second me dobara try kiya jayega...")
                time.sleep(5) # 5 second intezaar karein
                continue # Agli koshish ke liye loop continue karein

            response.raise_for_status() # Baaki errors (jaise 4xx) ke liye error raise karein
            
            response_json = response.json()
            candidate = response_json.get('candidates', [{}])[0]
            content_part = candidate.get('content', {}).get('parts', [{}])[0]
            ai_response_text = content_part.get('text', "AI se koi valid response nahi mila.")
            
            print_status("AI se suggestions mil gaye.")
            return ai_response_text 

        except requests.exceptions.RequestException as e:
            print_error(f"Attempt {attempt + 1}/{max_retries}: AI API se connect hone me truti hui: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
            else:
                return f"AI API Error: {e}" 
    
    return "AI API se connect hone me vifal, saari koshishein fail huin."

