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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from flask import Flask, render_template, request, jsonify

# Optimize requests session for better performance
def create_optimized_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=100,
        pool_maxsize=100
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# Global optimized session
optimized_session = create_optimized_session()


app = Flask(__name__)

# API key for AbuseIPDB
api_key = "36474dbff173efbdb763dc76a57a57237d569ef6b0d7c2f592bb842c6f3e098536968f53c803db02"
OTX_API_KEY="491c2539b77d9dbb4c6df06ad467cbc0e8de73064c45148e58a3663042b3902b"
 
# API key for VirusTotal
# To get your VirusTotal API key:
# 1. Sign up at https://www.virustotal.com/
# 2. Go to your profile settings
# 3. Generate an API key
# 4. Replace the value below with your actual API key
virustotal_api_key = "0fa15de267b5e0b41802cd23a8d6078b374cfd4bf20a3b22d88b64707c147eec"  # Replace with your VirusTotal API key

DB_PATH = 'ip_cache.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS ip_cache ('
            ' ip TEXT PRIMARY KEY,'
            ' abuseipdb_data TEXT NOT NULL,'
            ' virustotal_data TEXT,'
            ' otx_data TEXT,'
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
        cur.execute('SELECT abuseipdb_data, virustotal_data, otx_data FROM ip_cache WHERE ip = ?', (ip,))
        row = cur.fetchone()
        if row:
            try:
                abuseipdb_data = json.loads(row[0]) if row[0] else None
                virustotal_data = json.loads(row[1]) if row[1] else None
                otx_data = json.loads(row[2]) if row[2] else None
                
                # If we have old-style cached data, convert it
                if abuseipdb_data and ('abuseConfidencePercentage' in abuseipdb_data or 'abuseConfidenceScore' in abuseipdb_data):
                    # Convert old format to new format
                    abuseipdb_data = {
                        'ipAddress': abuseipdb_data.get('ipAddress', ip),
                        'isPublic': abuseipdb_data.get('isPublic', False),
                        'ipVersion': abuseipdb_data.get('ipVersion', 4),
                        'isWhitelisted': abuseipdb_data.get('isWhitelisted', False),
                        'abuseConfidenceScore': abuseipdb_data.get('abuseConfidenceScore', abuseipdb_data.get('abuseConfidencePercentage', 0)),
                        'countryCode': abuseipdb_data.get('countryCode', 'N/A'),
                        'usageType': abuseipdb_data.get('usageType', 'N/A'),
                        'isp': abuseipdb_data.get('isp', 'N/A'),
                        'domain': abuseipdb_data.get('domain', 'N/A'),
                        'hostnames': abuseipdb_data.get('hostnames', []),
                        'isTor': abuseipdb_data.get('isTor', False),
                        'totalReports': abuseipdb_data.get('totalReports', 0),
                        'numDistinctUsers': abuseipdb_data.get('numDistinctUsers', 0),
                        'lastReportedAt': abuseipdb_data.get('lastReportedAt', 'N/A'),
                        'status': 'success'
                    }
                
                return {
                    'abuseipdb': abuseipdb_data,
                    'virustotal': virustotal_data,
                    'otx': otx_data
                }
            except Exception as e:
                print(f"Error parsing cached data for {ip}: {e}")
                return None
        return None
    finally:
        conn.close()

def set_cached_ip(ip, abuseipdb_data=None, virustotal_data=None, otx_data=None):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        
        # Check if IP already exists
        cur.execute('SELECT abuseipdb_data, virustotal_data, otx_data FROM ip_cache WHERE ip = ?', (ip,))
        existing = cur.fetchone()
        
        # Merge existing data with new data
        if existing:
            existing_abuseipdb = json.loads(existing[0]) if existing[0] else None
            existing_virustotal = json.loads(existing[1]) if existing[1] else None
            existing_otx = json.loads(existing[2]) if existing[2] else None
            
            final_abuseipdb = abuseipdb_data if abuseipdb_data is not None else existing_abuseipdb
            final_virustotal = virustotal_data if virustotal_data is not None else existing_virustotal
            final_otx = otx_data if otx_data is not None else existing_otx
        else:
            final_abuseipdb = abuseipdb_data
            final_virustotal = virustotal_data
            final_otx = otx_data
        
        cur.execute(
            'INSERT OR REPLACE INTO ip_cache (ip, abuseipdb_data, virustotal_data, otx_data, updated_at) VALUES (?, ?, ?, ?, ?)',
            (ip, json.dumps(final_abuseipdb) if final_abuseipdb else None, 
             json.dumps(final_virustotal) if final_virustotal else None,
             json.dumps(final_otx) if final_otx else None, time.time())
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

def check_virustotal_ip(ip, api_key):
    """
    Check IP address against VirusTotal API
    Returns dictionary with VirusTotal data or error information
    """
    try:
        # VirusTotal API endpoint for IP address reports
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }
        
        response = optimized_session.get(url, headers=headers, timeout=8)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'malicious_votes': data['data']['attributes']['last_analysis_stats'].get('malicious', 0),
                'suspicious_votes': data['data']['attributes']['last_analysis_stats'].get('suspicious', 0),
                'harmless_votes': data['data']['attributes']['last_analysis_stats'].get('harmless', 0),
                'undetected_votes': data['data']['attributes']['last_analysis_stats'].get('undetected', 0),
                'total_engines': sum(data['data']['attributes']['last_analysis_stats'].values()),
                'reputation': data['data']['attributes'].get('reputation', 0),
                'country': data['data']['attributes'].get('country', 'N/A'),
                'as_owner': data['data']['attributes'].get('as_owner', 'N/A'),
                'last_analysis_date': data['data']['attributes'].get('last_analysis_date', None),
                'status': 'success'
            }
        elif response.status_code == 404:
            return {
                'ip': ip,
                'status': 'not_found',
                'error': 'IP not found in VirusTotal database'
            }
        elif response.status_code == 401:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'VirusTotal API authentication failed - please check your API key'
            }
        elif response.status_code == 403:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'VirusTotal API access forbidden - check your API key permissions'
            }
        elif response.status_code == 429:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'VirusTotal API rate limit exceeded - please wait and try again'
            }
        else:
            return {
                'ip': ip,
                'status': 'error',
                'error': f'VirusTotal API error: HTTP {response.status_code} - {response.text[:100] if response.text else "Unknown error"}'
            }
    except requests.exceptions.Timeout:
        return {
            'ip': ip,
            'status': 'error',
            'error': 'VirusTotal API timeout'
        }
    except Exception as e:
        return {
            'ip': ip,
            'status': 'error',
            'error': f'VirusTotal check failed: {str(e)}'
        }

def check_otx_ip(ip, api_key):
    """
    Check IP address against OTX (Open Threat Exchange) API
    Returns dictionary with OTX data or error information
    """
    try:
        # OTX API endpoint for IP address general data
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": api_key}
        
        response = optimized_session.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            country = data.get("country_code", "Unknown")
            
            # Get ISP information for whitelist check
            isp = data.get("asn", "Unknown")
            
            # Whitelist for legitimate Saudi telecom companies and organizations
            saudi_telecom_whitelist = [
                "saudi telecom", "stc", "etihad etisalat", "mobily", 
                "arabian internet", "communications services", "ministry",
                "government", "hospital", "foundation", "engineering",
                "saudi arabia", "ksa", "kingdom", "royal", "national",
                "awal", "tamimi", "mtc", "atheeb", "integrated telecom"
            ]
            
            # Check if ISP is in whitelist (case insensitive) OR if it's from Saudi Arabia
            is_whitelisted = (
                any(whitelist_term.lower() in isp.lower() 
                    for whitelist_term in saudi_telecom_whitelist) or
                country == 'SA'  # Saudi Arabia country code
            )
            
            # Much more conservative risk calculation
            if is_whitelisted:
                # For whitelisted ISPs, only flag if very high pulse count
                if pulse_count >= 20:
                    risk = "MEDIUM"
                    score = 30
                elif pulse_count >= 10:
                    risk = "LOW"
                    score = 15
                else:
                    risk = "CLEAN"
                    score = 0
            else:
                # For non-whitelisted ISPs, use original logic but more conservative
                if pulse_count >= 10:
                    risk = "HIGH"
                    score = 80
                elif pulse_count >= 5:
                    risk = "MEDIUM" 
                    score = 50
                elif pulse_count >= 2:
                    risk = "LOW"
                    score = 25
                else:
                    risk = "CLEAN"
                    score = 0
            
            # Country bonus for high-risk countries (but not for whitelisted ISPs)
            if not is_whitelisted and country in ['RU', 'CN', 'KP', 'IR']:
                score += 20
                if risk == "CLEAN":
                    risk = "LOW"
                elif risk == "LOW":
                    risk = "MEDIUM"
            
            return {
                'ip': ip,
                'risk': risk,
                'score': min(score, 100),
                'pulses': pulse_count,
                'country': country,
                'isp': isp,
                'whitelisted': is_whitelisted,
                'status': 'success'
            }
        elif response.status_code == 404:
            return {
                'ip': ip,
                'risk': 'CLEAN',
                'score': 0,
                'pulses': 0,
                'country': 'Unknown',
                'isp': 'Unknown',
                'whitelisted': False,
                'status': 'not_found'
            }
        elif response.status_code == 401:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'OTX API authentication failed - please check your API key'
            }
        elif response.status_code == 403:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'OTX API access forbidden - check your API key permissions'
            }
        elif response.status_code == 429:
            return {
                'ip': ip,
                'status': 'error',
                'error': 'OTX API rate limit exceeded - please wait and try again'
            }
        else:
            return {
                'ip': ip,
                'status': 'error',
                'error': f'OTX API error: HTTP {response.status_code} - {response.text[:100] if response.text else "Unknown error"}'
            }
    except requests.exceptions.Timeout:
        return {
            'ip': ip,
            'status': 'error',
            'error': 'OTX API timeout'
        }
    except Exception as e:
        return {
            'ip': ip,
            'status': 'error',
            'error': f'OTX check failed: {str(e)}'
        }

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

        # Separate cached vs to-fetch for all APIs
        to_fetch_abuseipdb = []
        to_fetch_virustotal = []
        to_fetch_otx = []
        
        for ip in external_ips:
            cached = get_cached_ip(ip)
            if cached is not None:
                # Merge cached data into final output
                final_data = {}
                
                # Add AbuseIPDB data if available
                if cached.get('abuseipdb'):
                    abuseipdb_data = cached['abuseipdb']
                    final_data.update(abuseipdb_data)
                    # Ensure all required fields exist with default values
                    final_data.setdefault('ipAddress', ip)
                    final_data.setdefault('isp', 'N/A')
                    final_data.setdefault('domain', 'N/A')
                    final_data.setdefault('countryCode', 'N/A')
                    final_data.setdefault('totalReports', 0)
                    final_data.setdefault('lastReportedAt', 'N/A')
                    final_data.setdefault('abuseConfidenceScore', 0)
                else:
                    # If no cached AbuseIPDB data, create default structure
                    final_data = {
                        'ipAddress': ip,
                        'isp': 'N/A',
                        'domain': 'N/A',
                        'countryCode': 'N/A',
                        'totalReports': 0,
                        'lastReportedAt': 'N/A',
                        'abuseConfidenceScore': 0,
                        'error': 'AbuseIPDB data not available'
                    }
                
                # Add VirusTotal data if available
                if cached.get('virustotal'):
                    final_data['virustotal'] = cached['virustotal']
                
                # Add OTX data if available
                if cached.get('otx'):
                    final_data['otx'] = cached['otx']
                
                output_data.append(final_data)
            else:
                to_fetch_abuseipdb.append(ip)
                to_fetch_virustotal.append(ip)
                to_fetch_otx.append(ip)

        # Optimized worker count - much more aggressive threading
        total_ips = len(to_fetch_abuseipdb)
        if total_ips > 0:
            # Scale workers based on IP count: 20-100 threads for better performance
            num_workers = max(20, min(100, total_ips * 2))
        else:
            num_workers = 0

        # Queues for tasks and results
        abuseipdb_queue = queue.Queue()
        virustotal_queue = queue.Queue()
        otx_queue = queue.Queue()
        result_queue = queue.Queue()

        # Add IPs to all queues
        for ip in to_fetch_abuseipdb:
            abuseipdb_queue.put(ip)
        for ip in to_fetch_virustotal:
            virustotal_queue.put(ip)
        for ip in to_fetch_otx:
            otx_queue.put(ip)

        def abuseipdb_worker():
            while True:
                try:
                    ip = abuseipdb_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    # Use the working approach from the old code
                    response = requests.get(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                        headers={'Accept': 'application/json', 'Key': api_key},
                        timeout=10
                    )
                    if response.status_code == 200:
                        raw_data = response.json()['data']
                        # The API already returns the correct field names, just use them directly
                        data = {
                            'ipAddress': raw_data.get('ipAddress', ip),
                            'isPublic': raw_data.get('isPublic', False),
                            'ipVersion': raw_data.get('ipVersion', 4),
                            'isWhitelisted': raw_data.get('isWhitelisted', False),
                            'abuseConfidenceScore': raw_data.get('abuseConfidenceScore', 0),  # Fixed: use correct field name
                            'countryCode': raw_data.get('countryCode', 'N/A'),
                            'usageType': raw_data.get('usageType', 'N/A'),
                            'isp': raw_data.get('isp', 'N/A'),
                            'domain': raw_data.get('domain', 'N/A'),
                            'hostnames': raw_data.get('hostnames', []),
                            'isTor': raw_data.get('isTor', False),
                            'totalReports': raw_data.get('totalReports', 0),
                            'numDistinctUsers': raw_data.get('numDistinctUsers', 0),
                            'lastReportedAt': raw_data.get('lastReportedAt', 'N/A'),
                            'status': 'success'
                        }
                        print(f"✅ AbuseIPDB success for {ip}: Score={data['abuseConfidenceScore']}, ISP={data['isp']}")
                    else:
                        data = {'ipAddress': ip, 'error': f'HTTP {response.status_code}'}
                        print(f"❌ AbuseIPDB error for {ip}: HTTP {response.status_code}")
                    
                    # Cache AbuseIPDB data
                    set_cached_ip(ip, abuseipdb_data=data)
                    result_queue.put(('abuseipdb', ip, data))
                except requests.exceptions.Timeout:
                    result_queue.put(('abuseipdb', ip, {'ipAddress': ip, 'error': 'AbuseIPDB API timeout - request took too long'}))
                except Exception as fetch_err:
                    result_queue.put(('abuseipdb', ip, {'ipAddress': ip, 'error': f'AbuseIPDB check failed: {str(fetch_err)}'}))
                finally:
                    abuseipdb_queue.task_done()

        def virustotal_worker():
            while True:
                try:
                    ip = virustotal_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    data = check_virustotal_ip(ip, virustotal_api_key)
                    
                    # Cache VirusTotal data
                    set_cached_ip(ip, virustotal_data=data)
                    result_queue.put(('virustotal', ip, data))
                except Exception as fetch_err:
                    result_queue.put(('virustotal', ip, {'ip': ip, 'error': f'VT error: {str(fetch_err)}'}))
                finally:
                    virustotal_queue.task_done()

        def otx_worker():
            while True:
                try:
                    ip = otx_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    data = check_otx_ip(ip, OTX_API_KEY)
                    
                    # Cache OTX data
                    set_cached_ip(ip, otx_data=data)
                    result_queue.put(('otx', ip, data))
                except Exception as fetch_err:
                    result_queue.put(('otx', ip, {'ip': ip, 'error': f'OTX error: {str(fetch_err)}'}))
                finally:
                    otx_queue.task_done()

        # Start threads for all APIs - OPTIMIZED FOR SPEED
        threads = []
        
        # AbuseIPDB threads - More aggressive threading
        abuseipdb_workers = min(30, num_workers) if num_workers > 0 else 0
        for _ in range(abuseipdb_workers):
            t = threading.Thread(target=abuseipdb_worker, daemon=True)
            t.start()
            threads.append(t)
        
        # VirusTotal threads - Increased for better performance
        vt_workers = min(15, num_workers) if num_workers > 0 else 0
        for _ in range(vt_workers):
            t = threading.Thread(target=virustotal_worker, daemon=True)
            t.start()
            threads.append(t)
        
        # OTX threads - Much more aggressive (OTX is fast)
        otx_workers = min(25, num_workers) if num_workers > 0 else 0
        for _ in range(otx_workers):
            t = threading.Thread(target=otx_worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all tasks to finish with timeout
        start_time = time.time()
        timeout = 60  # 60 second timeout
        
        if abuseipdb_workers > 0:
            abuseipdb_queue.join()
        if vt_workers > 0:
            virustotal_queue.join()
        if otx_workers > 0:
            otx_queue.join()
            
        elapsed = time.time() - start_time
        print(f"⚡ API calls completed in {elapsed:.2f} seconds")

        # Collect results and merge by IP - OPTIMIZED
        results_by_ip = {}
        total_expected = len(to_fetch_abuseipdb) * 3  # 3 APIs per IP
        completed = 0
        
        while not result_queue.empty():
            api_type, ip, data = result_queue.get()
            if ip not in results_by_ip:
                results_by_ip[ip] = {}
            results_by_ip[ip][api_type] = data
            completed += 1
            
            # Progress indicator for large batches
            if total_expected > 50 and completed % 10 == 0 and total_expected > 0:
                progress = (completed / total_expected) * 100
                print(f"📊 Progress: {completed}/{total_expected} API calls ({progress:.1f}%)")

        # Merge results and add to output_data
        for ip, ip_results in results_by_ip.items():
            final_data = {}
            
            # Add AbuseIPDB data with default values
            if 'abuseipdb' in ip_results:
                abuseipdb_data = ip_results['abuseipdb']
                final_data.update(abuseipdb_data)
                # Ensure all required fields exist with default values
                final_data.setdefault('ipAddress', ip)
                final_data.setdefault('isp', 'N/A')
                final_data.setdefault('domain', 'N/A')
                final_data.setdefault('countryCode', 'N/A')
                final_data.setdefault('totalReports', 0)
                final_data.setdefault('lastReportedAt', 'N/A')
                final_data.setdefault('abuseConfidenceScore', 0)
            else:
                # If no AbuseIPDB data, create default structure
                final_data = {
                    'ipAddress': ip,
                    'isp': 'N/A',
                    'domain': 'N/A',
                    'countryCode': 'N/A',
                    'totalReports': 0,
                    'lastReportedAt': 'N/A',
                    'abuseConfidenceScore': 0,
                    'error': 'AbuseIPDB data not available'
                }
            
            # Add VirusTotal data
            if 'virustotal' in ip_results:
                final_data['virustotal'] = ip_results['virustotal']
            
            # Add OTX data
            if 'otx' in ip_results:
                final_data['otx'] = ip_results['otx']
            
            output_data.append(final_data)

        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_minutes, elapsed_seconds = divmod(elapsed_time, 60)
        elapsed_minutes = math.floor(elapsed_minutes)
        elapsed_seconds = round(elapsed_seconds, 1)
        avg_time_per_ip = round(elapsed_time / total_rows, 1) if total_rows > 0 else 0
        
        # Performance summary
        print(f"🚀 PERFORMANCE SUMMARY:")
        print(f"   Total IPs: {total_rows}")
        print(f"   Total time: {elapsed_minutes}m {elapsed_seconds}s")
        print(f"   Avg per IP: {avg_time_per_ip}s")
        print(f"   Threads used: {abuseipdb_workers + vt_workers + otx_workers}")
        print(f"   Speed: {total_rows/elapsed_time:.1f} IPs/second" if elapsed_time > 0 else "   Speed: N/A IPs/second")

        # Separate high-risk IPs (score > 80 and not major cloud providers, or VirusTotal malicious)
        high_risk_ips = []
        safe_ips = []
        
        print("=== DEBUGGING HIGH RISK IP LOGIC ===")
        for ip_data in output_data:
            print(f"Processing IP: {ip_data.get('ipAddress', 'N/A')}")
            print(f"  AbuseIPDB Score: {ip_data.get('abuseConfidenceScore', 'N/A')}")
            print(f"  ISP: {ip_data.get('isp', 'N/A')}")
            
            # Check VirusTotal data
            vt_data = ip_data.get('virustotal', {})
            vt_malicious = vt_data.get('malicious_votes', 0) if vt_data else 0
            vt_suspicious = vt_data.get('suspicious_votes', 0) if vt_data else 0
            print(f"  VirusTotal Malicious: {vt_malicious}, Suspicious: {vt_suspicious}")
            
            # Check OTX data
            otx_data = ip_data.get('otx', {})
            otx_risk = otx_data.get('risk', 'CLEAN') if otx_data else 'CLEAN'
            otx_score = otx_data.get('score', 0) if otx_data else 0
            otx_pulses = otx_data.get('pulses', 0) if otx_data else 0
            print(f"  OTX Risk: {otx_risk}, Score: {otx_score}, Pulses: {otx_pulses}")
            
            is_high_risk = False
            risk_reasons = []
            
            # Check AbuseIPDB score
            if 'abuseConfidenceScore' in ip_data and ip_data['abuseConfidenceScore'] > 80:
                isp = ip_data.get('isp', '').lower()
                if not any(provider in isp for provider in ['microsoft', 'amazon', 'alibaba', 'google']):
                    is_high_risk = True
                    risk_reasons.append("AbuseIPDB Score > 80% (not major cloud provider)")
                else:
                    risk_reasons.append("AbuseIPDB Score > 80% but major cloud provider")
            
            # Check VirusTotal malicious votes - FIXED: Require multiple detections
            if vt_malicious >= 2:  # Require at least 2 malicious detections
                is_high_risk = True
                risk_reasons.append(f"VirusTotal: {vt_malicious} malicious detection(s)")
            
            # Check VirusTotal suspicious votes (lower threshold)
            if vt_suspicious >= 3:  # 3 or more suspicious detections
                is_high_risk = True
                risk_reasons.append(f"VirusTotal: {vt_suspicious} suspicious detection(s)")
            
            # Check OTX risk level - FIXED: Only flag if not whitelisted and truly high risk
            if otx_data and not otx_data.get('whitelisted', False):  # Skip whitelisted ISPs
                if otx_risk == 'HIGH' and otx_score >= 80:  # Only flag truly high risk
                    is_high_risk = True
                    risk_reasons.append(f"OTX: {otx_risk} risk ({otx_score}/100, {otx_pulses} pulses)")
                elif otx_risk == 'MEDIUM' and otx_score >= 70:  # Only flag high medium risk
                    is_high_risk = True
                    risk_reasons.append(f"OTX: {otx_risk} risk ({otx_score}/100, {otx_pulses} pulses)")
            
            if is_high_risk:
                print(f"  -> HIGH RISK ({', '.join(risk_reasons)})")
                high_risk_ips.append(ip_data)
            else:
                print(f"  -> SAFE (AbuseIPDB: {ip_data.get('abuseConfidenceScore', 'N/A')}, VT: {vt_malicious}M/{vt_suspicious}S, OTX: {otx_risk})")
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


@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/check-ips', methods=['POST'])
def check_ips():
    """API endpoint for checking IP addresses"""
    global api_key
    
    try:
        # Get data from request
        data = request.get_json()
        input_text = data.get('input_text', '') if data else ''
        input_csv_data = data.get('input_csv_data', '') if data else ''
        
        # Process the input
        if input_csv_data:
            # Process CSV data
            import io
            csv_file = io.StringIO(input_csv_data)
            result = bulk_check(file=csv_file, api_key=api_key)
        elif input_text:
            # Process text input
            result = bulk_check(text=input_text, api_key=api_key)
        else:
            return jsonify({'error': 'No input data provided'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=False)
