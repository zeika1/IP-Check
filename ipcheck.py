import pandas as pd
import requests
import tkinter as tk
from tkinter import filedialog
import sys
import os
import concurrent.futures
from itertools import cycle

# --- CONFIGURATION ---

IP_COLUMN_NAME = 'Attacker IP' 
DELIMITER = ':'

# REPLACE THESE WITH YOUR NEW KEYS
API_KEYS = [
    '7dbbab16e7929072ec9a3301594f0abd5a6d6053ff1305b22b361e3feefda84886804191db932a47',

    'a6fb5bb4e5967f734ac6179174250140bfb4e2ac9924f4429f71d1df205d941a8085b0ab0fa04b1b',

    '5e5e510dcdbdbf1dd54c1bac80b5bf55b927bb6c6a86cd4f471f85d5a5212a4726cf94b23014d032'
]

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
MAX_WORKERS = 10  # Number of simultaneous requests (Don't go too high or you'll trigger firewall blocks)

# --- STEP 1: FILE SELECTION AND CLEANING ---

# Initialize Tkinter (hidden root window)
root = tk.Tk()
root.withdraw() 

print("Waiting for file selection...")
FILE_PATH = filedialog.askopenfilename(
    title="Select your CSV file containing IP addresses",
    filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
)

if not FILE_PATH:
    print("No file selected. Exiting program.")
    sys.exit()

print(f"Selected file: {FILE_PATH}")

try:
    df = pd.read_csv(FILE_PATH)
    
    if IP_COLUMN_NAME not in df.columns:
        print(f"Error: Column '{IP_COLUMN_NAME}' not found. Update IP_COLUMN_NAME in script.")
        sys.exit()
        
    original_count = len(df)
    # Create a list of unique IPs to check
    unique_ips = df[IP_COLUMN_NAME].drop_duplicates().tolist()
    
    print(f"Original rows: {original_count}")
    print(f"Unique IPs to check: {len(unique_ips)}")
    
except Exception as e:
    print(f"An error occurred during file processing: {e}")
    sys.exit()

# --- STEP 2: DEFINE WORKER FUNCTION ---

# Create a session to reuse TCP connections (faster)
session = requests.Session()

def check_ip(ip, api_key):
    """Checks a single IP using the assigned API key."""
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    result_data = {
        'usage_type': 'Unknown', 
        'is_hosting': False, 
        'is_checked': False, 
        'error': None
    }

    try:
        response = session.get(ABUSEIPDB_URL, headers=headers, params=querystring, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                usage_type = data['data'].get('usageType', 'Unknown')
                # Check for hosting indicators
                is_hosting = any(x in str(usage_type) for x in ["Data Center", "Web Hosting", "Hosting"])
                
                result_data['usage_type'] = usage_type
                result_data['is_hosting'] = is_hosting
                result_data['is_checked'] = True
        elif response.status_code == 429:
            result_data['error'] = "Rate Limit Exceeded (429)"
        else:
            result_data['error'] = f"Status {response.status_code}"
            
    except Exception as e:
        result_data['error'] = str(e)
        
    return ip, result_data

# --- STEP 3: PARALLEL EXECUTION ---

results = {}
key_cycler = cycle(API_KEYS) # Creates an infinite loop of the keys: 1, 2, 3, 1, 2...

print(f"\n--- Starting checks with {MAX_WORKERS} threads ---")
print("Please wait...")

# ThreadPoolExecutor manages the parallel workers
with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    # Submit all tasks to the pool
    # We zip unique_ips with the key_cycler to assign a rotating key to every IP
    future_to_ip = {
        executor.submit(check_ip, ip, next(key_cycler)): ip 
        for ip in unique_ips
    }
    
    # Process results as they complete
    completed_count = 0
    for future in concurrent.futures.as_completed(future_to_ip):
        ip, data = future.result()
        results[ip] = data
        
        completed_count += 1
        if completed_count % 50 == 0:
            print(f"Processed {completed_count}/{len(unique_ips)} IPs...")

# --- STEP 4: OUTPUT RESULTS ---

print("\n--- Processing Complete. Saving... ---")

# Convert results dictionary to DataFrame
results_df = pd.DataFrame.from_dict(results, orient='index')
results_df.index.name = IP_COLUMN_NAME
results_df.reset_index(inplace=True)

# Merge back with original dataframe to keep all original rows
final_df = df.merge(results_df, on=IP_COLUMN_NAME, how='left')

# Fill NaNs for display
final_df['is_checked'] = final_df['is_checked'].fillna(False)
final_df['is_hosting'] = final_df['is_hosting'].fillna(False)
final_df['usage_type'] = final_df['usage_type'].fillna('Not Checked')

# Generate filename
base_name = os.path.splitext(os.path.basename(FILE_PATH))[0]
output_file_name = f'{base_name}_abuseipdb_results.csv'

final_df.to_csv(output_file_name, index=False)

hosting_count = final_df[final_df['is_hosting'] == True].shape[0]

print("\n--- FINAL SUMMARY ---")
print(f"Total IPs Checked: {final_df['is_checked'].sum()}")
print(f"Hosting/Data Center IPs found: {hosting_count}")
print(f"Results saved to: {output_file_name}")