import csv
import time
import math
import requests
import ipaddress
import re
import sqlite3
import json
import threading
import queue
import os
from flask import Flask, render_template, request, jsonify


app = Flask(__name__)

# API key for AbuseIPDB
api_key = "afff296b18e8be5f55036f9910acb04749ea415b10952bef60bd2fe4adff8fe3722bc5de3f8eddcc"

DB_PATH = 'ip_cache.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS ip_cache ('
            ' ip TEXT PRIMARY KEY,'
            ' data TEXT NOT NULL,'
            ' updated_at REAL NOT NULL'
            ')'
        )
        conn.commit()
    finally:
        conn.close()

def get_cached_ip(ip):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute('SELECT data FROM ip_cache WHERE ip = ?', (ip,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(row[0])
            except Exception:
                return None
        return None
    finally:
        conn.close()

def set_cached_ip(ip, data):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            'INSERT OR REPLACE INTO ip_cache (ip, data, updated_at) VALUES (?, ?, ?)',
            (ip, json.dumps(data), time.time())
        )
        conn.commit()
    finally:
        conn.close()

init_db()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def bulk_check(file=None, text=None, api_key=None):
    start_time = time.time()
    output_data = []
    ip_list = []

    try:
        if file:  # Process CSV file
            file.seek(0)
            csv_reader = csv.reader(file.read().decode('utf-8').splitlines())
            for row in csv_reader:
                ip_list.append(row[0])
        elif text:  # Process text area input
            # Updated regex pattern to capture IPs embedded in text
            ip_list = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)

        # Remove duplicate IPs
        ip_list = list(set(ip_list))

        # Output the regexed IPs to the console for testing
        print("Unique IPs:", ip_list)

        # Filter out internal IPs and invalid IPs
        external_ips = []
        for ip in ip_list:
            if is_valid_ip(ip):
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    external_ips.append(ip)

        total_rows = len(external_ips)

        # Separate cached vs to-fetch
        to_fetch_ips = []
        for ip in external_ips:
            cached = get_cached_ip(ip)
            if cached is not None:
                output_data.append(cached)
            else:
                to_fetch_ips.append(ip)

        # Determine worker count between 10 and 50 based on workload
        num_workers = max(10, min(50, len(to_fetch_ips))) if len(to_fetch_ips) > 0 else 0

        # Queues for tasks and results
        task_queue = queue.Queue()
        result_queue = queue.Queue()

        for ip in to_fetch_ips:
            task_queue.put(ip)

        def worker():
            while True:
                try:
                    ip = task_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    response = requests.get(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                        headers={'Accept': 'application/json', 'Key': api_key}
                    )
                    if response.status_code == 200:
                        data = response.json()['data']
                    else:
                        data = {'ipAddress': ip, 'error': 'Invalid IP'}
                    set_cached_ip(ip, data)
                    result_queue.put(data)
                except Exception as fetch_err:
                    result_queue.put({'ipAddress': ip, 'error': f'Fetch error: {str(fetch_err)}'})
                finally:
                    task_queue.task_done()

        threads = []
        for _ in range(num_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all tasks to finish
        if num_workers > 0:
            task_queue.join()

        # Drain results
        while not result_queue.empty():
            output_data.append(result_queue.get())

        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_minutes, elapsed_seconds = divmod(elapsed_time, 60)
        elapsed_minutes = math.floor(elapsed_minutes)
        elapsed_seconds = round(elapsed_seconds, 1)
        avg_time_per_ip = round(elapsed_time / total_rows, 1) if total_rows > 0 else 0

        # Separate high-risk IPs (score > 80 and not major cloud providers)
        high_risk_ips = []
        safe_ips = []
        
        print("=== DEBUGGING HIGH RISK IP LOGIC ===")
        for ip_data in output_data:
            print(f"Processing IP: {ip_data.get('ipAddress', 'N/A')}")
            print(f"  Score: {ip_data.get('abuseConfidenceScore', 'N/A')}")
            print(f"  ISP: {ip_data.get('isp', 'N/A')}")
            
            if 'abuseConfidenceScore' in ip_data and ip_data['abuseConfidenceScore'] > 80:
                # Check if ISP is not a major cloud provider
                isp = ip_data.get('isp', '').lower()
                if not any(provider in isp for provider in ['microsoft', 'amazon', 'alibaba', 'google']):
                    print(f"  -> HIGH RISK (Score > 80, not major cloud provider)")
                    high_risk_ips.append(ip_data)
                else:
                    print(f"  -> SAFE (Score > 80, but major cloud provider)")
                    safe_ips.append(ip_data)
            else:
                print(f"  -> SAFE (Score <= 80)")
                safe_ips.append(ip_data)
        
        print(f"Total high risk IPs found: {len(high_risk_ips)}")
        print(f"High risk IPs: {[ip.get('ipAddress') for ip in high_risk_ips]}")
        print("=== END DEBUGGING ===")

        result = {
            'output_data': output_data,
            'high_risk_ips': high_risk_ips,
            'safe_ips': safe_ips,
            'total_rows': total_rows,
            'elapsed_minutes': elapsed_minutes,
            'elapsed_seconds': elapsed_seconds,
            'avg_time_per_ip': avg_time_per_ip
        }
        
        print("=== RETURNING RESULT ===")
        print(f"Output data count: {len(result['output_data'])}")
        print(f"High risk IPs count: {len(result['high_risk_ips'])}")
        print(f"Safe IPs count: {len(result['safe_ips'])}")
        print("=== END RETURNING ===")
        
        return result

    except Exception as e:
        return {
            'error': f"An error occurred: {str(e)}"
        }


@app.route('/', methods=['GET', 'POST'])
def index():
    global api_key

    if request.method == 'POST':
        input_csv = request.files.get('input_csv')
        input_text = request.form.get('input_text')

        if input_csv or input_text:
            result = bulk_check(file=input_csv, text=input_text, api_key=api_key)
            return jsonify(result)  # Return JSON response

    return render_template('index.html')

if __name__ == '__main__':
    app.run(port=5000, debug=False)
