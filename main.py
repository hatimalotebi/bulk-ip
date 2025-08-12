import csv
import time
import math
import requests
import ipaddress
import re
from flask import Flask, render_template, request, jsonify


app = Flask(__name__)

api_key = ""  # AbuseIPDB API key

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

        for i, ip in enumerate(external_ips):
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={'Accept': 'application/json', 'Key': api_key}
            )

            if response.status_code == 200:
                output_data.append(response.json()['data'])
            else:
                output_data.append({'ipAddress': ip, 'error': 'Invalid IP'})

        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_minutes, elapsed_seconds = divmod(elapsed_time, 60)
        elapsed_minutes = math.floor(elapsed_minutes)
        elapsed_seconds = round(elapsed_seconds, 1)
        avg_time_per_ip = round(elapsed_time / total_rows, 1) if total_rows > 0 else 0

        return {
            'output_data': output_data,
            'total_rows': total_rows,
            'elapsed_minutes': elapsed_minutes,
            'elapsed_seconds': elapsed_seconds,
            'avg_time_per_ip': avg_time_per_ip
        }

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
