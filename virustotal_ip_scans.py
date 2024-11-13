"""Virus Total IP Scan Automation Script """

# Usage: virustotal_ipscans.py ip_file.csv/.xls results_output_file.csv results_json_file.json

import json
import requests
import time
import pandas as pd
import csv
import argparse
import os

# Replace with your VirusTotal API key
API_KEY = 'your_api_key_here'

# VirusTotal IP lookup endpoint
url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'


# Function to query VirusTotal for an IP
def scan_ip(ip):
    params = {'apikey': API_KEY, 'ip': ip}
    response = requests.get(url, params=params)

    # Check if the response is valid (Status 200 OK)
    if response.status_code == 200:
        result = response.json()

        # Pretty print the JSON response for terminal readout
        print(f"\\n=== Analysis for IP: {ip} ===")
        print(json.dumps(result, indent=4))

        # Initialize empty values in case no stats are returned
        harmless, malicious, suspicious, undetected = 'N/A', 'N/A', 'N/A', 'N/A'

        # Extract and display key information if available
        if 'last_analysis_stats' in result:
            stats = result['last_analysis_stats']
            harmless = stats.get('harmless', 'N/A')
            malicious = stats.get('malicious', 'N/A')
            suspicious = stats.get('suspicious', 'N/A')
            undetected = stats.get('undetected', 'N/A')

            print(f"\\nIP: {ip} Analysis Stats:")
            print(f"Harmless: {harmless}")
            print(f"Malicious: {malicious}")
            print(f"Suspicious: {suspicious}")
            print(f"Undetected: {undetected}")

        # Handle last analysis results
        if 'last_analysis_results' in result:
            results = result['last_analysis_results']
            print("\\nLast Analysis Results by Source:")
            for source, data in results.items():
                category = data.get('category', 'N/A')
                result_status = data.get('result', 'N/A')
                print(f"{source}: {category} - {result_status}")

        # Return essential information for saving purposes
        return {
            'ip': ip,
            'harmless': harmless,
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': undetected,
            'full_result': result  # Optionally save the entire result for JSON output
        }
    else:
        print(f"Error querying IP {ip}: {response.status_code}")
        return None


# Function to save results to a JSON file (batch writing)
def save_results_to_json(results, output_file):
    with open(output_file, 'w') as outfile:
        json.dump(results, outfile, indent=4)


# Function to process CSV file
def process_csv(file_path, output_file, json_output_file):
    # Read the CSV file
    df = pd.read_csv(file_path)

    # Initialize result storage
    all_results = []

    # Prepare the CSV writer
    with open(output_file, 'w', newline='') as outfile:
        fieldnames = ['IP', 'Harmless', 'Malicious', 'Suspicious', 'Undetected']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in df['IP']:  # Assuming your CSV file has a column called 'IP'
            result = scan_ip(ip)
            if result:
                writer.writerow({
                    'IP': result['ip'],
                    'Harmless': result['harmless'],
                    'Malicious': result['malicious'],
                    'Suspicious': result['suspicious'],
                    'Undetected': result['undetected']
                })
                all_results.append(result)

            # Wait between requests to respect the API rate limit
            time.sleep(15)

    # Save all results to the JSON file
    save_results_to_json(all_results, json_output_file)


# Function to process Excel file
def process_excel(file_path, output_file, json_output_file):
    # Read the Excel file into a DataFrame
    df = pd.read_excel(file_path)

    # Initialize result storage
    all_results = []

    # Prepare the CSV writer
    with open(output_file, 'w', newline='') as outfile:
        fieldnames = ['IP', 'Harmless', 'Malicious', 'Suspicious', 'Undetected']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in df['IP']:  # Assuming your Excel file has a column called 'IP'
            result = scan_ip(ip)
            if result:
                writer.writerow({
                    'IP': result['ip'],
                    'Harmless': result['harmless'],
                    'Malicious': result['malicious'],
                    'Suspicious': result['suspicious'],
                    'Undetected': result['undetected']
                })
                all_results.append(result)

            # Wait between requests to respect the API rate limit
            time.sleep(15)

    # Save all results to the JSON file
    save_results_to_json(all_results, json_output_file)


# Main function to parse arguments and process the file
def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Scan IPs from a CSV or Excel file using VirusTotal API")
    parser.add_argument("file_path", help="Path to the CSV or Excel file containing IPs")
    parser.add_argument("output_file", help="Path to the output CSV file where results will be saved")
    parser.add_argument("json_output_file", help="Path to the output JSON file where results will be saved")

    # Parse the arguments
    args = parser.parse_args()
    file_path = args.file_path
    output_file = args.output_file
    json_output_file = args.json_output_file

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Error: The file {file_path} does not exist.")
        return

    # Determine the file type and process accordingly
    if file_path.endswith('.csv'):
        process_csv(file_path, output_file, json_output_file)
    elif file_path.endswith('.xls') or file_path.endswith('.xlsx'):
        process_excel(file_path, output_file, json_output_file)
    else:
        print("Error: Unsupported file format. Please provide a CSV or Excel file.")


# Entry point of the script
if __name__ == "__main__":
    main()
