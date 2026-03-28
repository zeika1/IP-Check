import pandas as pd
import requests
import json
import time
import sys
import concurrent.futures
import os

# --- CONFIGURATION ---

# 1. Update this to match your CSV Column Header exactly
IP_COLUMN_NAME = 'Attacker IP' 

# 2. Your API Keys (Add your 3 keys here)
API_KEYS = [
    'YOUR_KEY_1',
    'YOUR_KEY_2',
    'YOUR_KEY_3'
]

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
CHUNK_SIZE = 1000 
MAX_WORKERS = 10  # Parallel threads for speed

def check_ip_worker(ip, api_key):
    headers = {'Accept': 'application/json', 'Key': api_key}
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    
    result = {'ip_address': ip, 'usage_type': 'Error', 'is_hosting': False, 'is_checked': False}

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            data = response.json()
            usage_type = data['data'].get('usageType', 'Unknown')
            # Look for hosting keywords in the usage type string
            is_hosting = any(k in usage_type for k in ["Data Center", "Web Hosting", "Transit"])
            
            result.update({
                'usage_type': usage_type,
                'is_hosting': is_hosting,
                'is_checked': True
            })
        elif response.status_code == 429:
            result['usage_type'] = "Rate Limit Hit"
    except Exception:
        pass
        
    return result

def main():
    # Check if user provided a filename in the command line
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <your_file.csv>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    # Load and Clean Data
    try:
        # We use sep=None to let pandas 'sniff' if it's a comma or colon automatically
        df = pd.read_csv(file_path, sep=None, engine='python')
        
        if IP_COLUMN_NAME not in df.columns:
            print(f"Error: Column '{IP_COLUMN_NAME}' not found.")
            print(f"Available columns: {list(df.columns)}")
            sys.exit(1)
            
        df.drop_duplicates(subset=[IP_COLUMN_NAME], inplace=True)
        all_ips = df[IP_COLUMN_NAME].tolist()
        print(f"[*] Loaded {len(all_ips)} unique IPs.")

    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    # Assign Keys to Tasks
    tasks = []
    for i, chunk in enumerate([all_ips[i:i + CHUNK_SIZE] for i in range(0, len(all_ips), CHUNK_SIZE)]):
        if i < len(API_KEYS):
            for ip in chunk:
                tasks.append((ip, API_KEYS[i]))

    print(f"[*] Starting scan with {MAX_WORKERS} threads...")

    final_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_ip_worker, ip, key): ip for ip, key in tasks}
        
        count = 0
        for future in concurrent.futures.as_completed(futures):
            final_results.append(future.result())
            count += 1
            if count % 100 == 0:
                print(f"Progress: {count}/{len(tasks)} checked...")

    # Save Output
    results_df = pd.DataFrame(final_results)
    final_df = df.merge(results_df, left_on=IP_COLUMN_NAME, right_on='ip_address', how='left')
    
    output_file = f"results_{file_path}"
    final_df.to_csv(output_file, index=False)
    
    print(f"\n[+] Done! Found {final_df['is_hosting'].sum()} hosting/DC IPs.")
    print(f"[+] Saved to: {output_file}")

if __name__ == "__main__":
    main()
