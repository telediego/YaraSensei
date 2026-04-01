import argparse
import os
import re
import sys
import json
import base64
import requests
import google.generativeai as genai
from dotenv import load_dotenv


load_dotenv()

LLM_API_KEY = os.getenv("LLM_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"

if LLM_API_KEY:
    genai.configure(api_key=LLM_API_KEY)


# VIRUSTOTAL UTILITIES & INDICATORS

def extract_indicators(yara_rule: str):
    """Extracts common indicators (domains, IPs, hashes, URLs) from a YARA rule."""
    indicators = {"domain": [], "ip_address": [], "hash": [], "url": []}
    
    strings_section_match = re.search(r'strings:\s*(.*?)\s*condition:', yara_rule, re.DOTALL | re.IGNORECASE)
    if not strings_section_match:
        strings_section_match = re.search(r'strings:\s*(.*)', yara_rule, re.DOTALL | re.IGNORECASE)
        if not strings_section_match:
            return indicators

    quoted_strings = re.findall(r'"([^"]*)"', strings_section_match.group(1))

    for s in quoted_strings:
        if re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', s):
            if s not in indicators["hash"]: indicators["hash"].append(s)        
        elif re.fullmatch(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', s):
            if s not in indicators["ip_address"]: indicators["ip_address"].append(s)
        elif re.match(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', s):
            if s not in indicators["url"]: indicators["url"].append(s)
        elif re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$', s) and not re.fullmatch(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', s):
            if s not in indicators["domain"]: indicators["domain"].append(s)
            
    return indicators

def get_vt_data(indicator_type: str, indicator_value: str):
    """Fetches VirusTotal data for a given indicator."""
    if not VT_API_KEY:
        return None, "VT_API_KEY not configured."

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    
    if indicator_type == "hash":
        url = f"{VT_API_BASE_URL}/files/{indicator_value}"
    elif indicator_type == "domain":
        url = f"{VT_API_BASE_URL}/domains/{indicator_value}"
    elif indicator_type == "ip_address":
        url = f"{VT_API_BASE_URL}/ip_addresses/{indicator_value}"
    elif indicator_type == "url":
        encoded_url = base64.urlsafe_b64encode(indicator_value.encode('utf-8')).decode('utf-8').strip("=")
        url = f"{VT_API_BASE_URL}/urls/{encoded_url}"
    else:
        return None, "Invalid indicator type."

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.HTTPError as e:
        return None, f"VT HTTP Error: {e.response.status_code}"
    except Exception as e:
        return None, f"VT Connection Error: {e}"


# MAIN FUNCTIONS (CLI)

def assess_risk(yara_rule: str):
    """Extracts indicators and assesses risk by querying VirusTotal."""
    print("\n--- RISK ASSESSMENT ---")
    indicators = extract_indicators(yara_rule)
    
    has_indicators = any(indicators.values())
    if not has_indicators:
        print("[INFO] No common indicators found (hashes, IPs, domains, URLs).")
        return

    if not VT_API_KEY:
        print("[WARN] VT_API_KEY is missing. Showing only extracted indicators:")
        print(json.dumps(indicators, indent=2))
        return

    total_malicious = 0
    print("[INFO] Querying VirusTotal...", flush=True)
    
    for ind_type, values in indicators.items():
        for val in values:
            data, error = get_vt_data(ind_type, val)
            if error:
                print(f"  [ERROR] Querying {val}: {error}")
                continue
                
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            if malicious > 0:
                print(f"  [MALICIOUS] {val} ({ind_type}): {malicious} malicious detections.")
                total_malicious += malicious
            else:
                print(f"  [CLEAN] {val} ({ind_type}): 0 detections.")

    print("\n[RESULT] Overall Risk Level:")
    if total_malicious >= 8:
        print("  CRITICAL: Multiple malicious detections found in the rule's indicators.")
    elif total_malicious > 0:
        print("  HIGH: Malicious detections found. Investigation recommended.")
    else:
        print("  LOW: No malicious activity detected in the extracted indicators.")

def enhance(yara_rule: str, original_file_path: str):
    """Enhances the YARA rule using Gemini and saves it to a new file."""
    print("\n--- YARA RULE ENHANCEMENT ---")
    if not LLM_API_KEY:
        print("[ERROR] LLM_API_KEY not configured. Cannot enhance the rule.")
        return
        
    try:
        print("[INFO] Querying Gemini to optimize the rule...", flush=True)
        
        prompt = (
            "You are an expert security analyst specializing in YARA rules. "
            "Enhance the following YARA rule to be more precise, robust, and have a lower false positive rate. "
            "Respond ONLY with a valid JSON object containing two keys: "
            "'optimized_rule' (the full string of the new rule) and "
            "'suggestions' (a list of string bullet points explaining the improvements).\n\n"
            f"```yara\n{yara_rule}\n```"
        )
        
        model = genai.GenerativeModel('gemini-3-flash-preview')
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.18
            )
        )
        
        result = json.loads(response.text)
        print("\n[SUCCESS] Suggested improvements:")
        for sug in result.get('suggestions', []):
            print(f"  - {sug}")
            
        optimized_rule = result.get('optimized_rule')
        
        if optimized_rule:
            base_name, ext = os.path.splitext(original_file_path)
            new_file_path = f"{base_name}_fix{ext}"
            
            with open(new_file_path, 'w', encoding='utf-8') as f_out:
                f_out.write(optimized_rule)
                
            print(f"\n[OPTIMIZED RULE]: Successfully saved to '{new_file_path}'")
        else:
            print("\n[ERROR] The model did not return the optimized rule correctly.")
        
    except Exception as e:
        print(f"[ERROR] During enhancement: {e}")


def main():
    parser = argparse.ArgumentParser(description="YARA Sensei CLI - Lightweight YARA rule analysis")
    parser.add_argument("file", help="Path to the file containing the YARA rule (.yar)")
    parser.add_argument("-a", "--action", choices=["assess", "enhance", "all"], default="all", help="Action to perform")
    
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] The file '{args.file}' does not exist.")
        sys.exit(1)

    with open(args.file, 'r', encoding='utf-8') as f:
        yara_rule = f.read()

    if args.action in ["assess", "all"]:
        assess_risk(yara_rule)
    if args.action in ["enhance", "all"]:
        enhance(yara_rule, args.file)

if __name__ == "__main__":
    main()