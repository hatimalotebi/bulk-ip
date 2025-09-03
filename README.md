# Bulk IP Checker

A powerful web application for bulk checking IP addresses against the AbuseIPDB database to identify potentially malicious IPs. This tool is designed for security professionals, system administrators, and cybersecurity analysts who need to quickly assess the reputation of multiple IP addresses.

## 🚀 Features

- **Bulk IP Processing**: Check hundreds of IP addresses simultaneously
- **Multiple Input Methods**: 
  - Upload CSV files with IP addresses
  - Paste IP addresses directly into text area
  - Append additional IPs to existing lists
- **Real-time Threat Intelligence**: Integration with AbuseIPDB API for comprehensive threat data
- **Intelligent Caching**: SQLite database caching to avoid redundant API calls
- **Multi-threaded Processing**: Optimized performance with configurable worker threads (10-50)
- **Comprehensive Results**: 
  - Abuse confidence scores
  - ISP information
  - Geographic location (country code)
  - Total reports count
  - Last reported timestamp
- **Export Functionality**: Download results as CSV files
- **Splunk Integration**: Pre-generated Splunk queries for threat hunting
- **Modern Web Interface**: Clean, responsive design with DataTables integration

## 📋 Requirements

- Python 3.7+
- Flask web framework
- SQLite3 database
- Internet connection for AbuseIPDB API access

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/bulk-ip.git
   cd bulk-ip
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   - **Windows:**
     ```bash
     venv\Scripts\activate
     ```
   - **macOS/Linux:**
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

The application is pre-configured with an AbuseIPDB API key. If you need to use your own API key:

1. Sign up at [AbuseIPDB](https://www.abuseipdb.com/)
2. Get your API key from your dashboard
3. Replace the API key in `main.py`:
   ```python
   api_key = "your_api_key_here"
   ```

## 🚀 Usage

1. **Start the application**
   ```bash
   python main.py
   ```

2. **Open your web browser** and navigate to:
   ```
   http://127.0.0.1:5000
   ```

3. **Input IP addresses** using one of these methods:
   - **CSV Upload**: Upload a CSV file with IP addresses in the first column
   - **Text Input**: Paste IP addresses (one per line or separated by spaces)
   - **Append Mode**: Add more IPs to an existing list

4. **Submit** and wait for processing to complete

5. **Review Results**: View detailed threat intelligence for each IP

6. **Export Data**: Download results as CSV for further analysis

## 📊 Input Formats

### CSV Format
```csv
192.168.1.1
10.0.0.1
172.16.0.1
```

### Text Input
```
192.168.1.1
10.0.0.1
172.16.0.1
```

Or simply paste IPs separated by spaces or commas.

## 🔍 Output Data

For each IP address, the application provides:

- **IP Address**: The checked IP
- **Abuse Confidence Score**: Percentage indicating likelihood of malicious activity
- **ISP**: Internet Service Provider information
- **Domain**: Associated domain (if available)
- **Country Code**: Geographic location (ISO 3166-1 alpha-2)
- **Total Reports**: Number of abuse reports received
- **Last Reported At**: Timestamp of most recent report

## 🗄️ Database

The application uses SQLite for caching IP check results:
- **File**: `ip_cache.db`
- **Table**: `ip_cache`
- **Fields**: IP address, JSON data, timestamp
- **Purpose**: Avoid redundant API calls for previously checked IPs

## ⚡ Performance Features

- **Dynamic Worker Threads**: Automatically adjusts between 10-50 threads based on workload
- **Intelligent Caching**: Skips API calls for recently checked IPs
- **Batch Processing**: Processes multiple IPs simultaneously
- **Progress Indicators**: Real-time feedback during processing

## 🔧 Technical Details

### Architecture
- **Backend**: Flask web application
- **Database**: SQLite3 with JSON data storage
- **API Integration**: AbuseIPDB REST API v2
- **Frontend**: HTML5, CSS3, JavaScript with DataTables
- **Processing**: Multi-threaded with queue-based task management

### Key Functions
- `bulk_check()`: Main processing function
- `init_db()`: Database initialization
- `get_cached_ip()`: Retrieve cached results
- `set_cached_ip()`: Store results in cache
- `is_valid_ip()`: IP validation and filtering

### API Endpoints
- `GET /`: Main interface
- `POST /`: Process IP addresses and return results

## 📁 Project Structure

```
bulk-ip/
├── main.py              # Main Flask application
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── ip_cache.db          # SQLite cache database
├── templates/           # HTML templates
│   ├── index.html       # Main interface
│   └── result.html      # Results display
└── venv/                # Virtual environment
```

## 🚨 Security Considerations

- **API Key**: The AbuseIPDB API key is hardcoded in the application
- **Input Validation**: All IP addresses are validated before processing
- **Rate Limiting**: Respects AbuseIPDB API rate limits
- **Data Privacy**: No user data is stored beyond the cache database

## 🔄 API Rate Limits

The application respects AbuseIPDB's API rate limits:
- **Free Tier**: 1,000 requests per day
- **Paid Tiers**: Higher limits available
- **Rate Limiting**: Automatic throttling implemented

## 🐛 Troubleshooting

### Common Issues

1. **Application won't start**
   - Ensure virtual environment is activated
   - Check Python version (3.7+ required)
   - Verify all dependencies are installed

2. **API errors**
   - Check internet connection
   - Verify API key is valid
   - Check AbuseIPDB service status

3. **Performance issues**
   - Reduce number of concurrent IPs
   - Check system resources
   - Monitor API rate limits

### Debug Mode

To enable debug mode, modify `main.py`:
```python
if __name__ == '__main__':
    app.run(port=5000, debug=True)  # Change to True
```



## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com/) for providing the threat intelligence API
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [DataTables](https://datatables.net/) for the interactive table functionality


---

**Note**: This tool is designed for legitimate security research and threat intelligence purposes. Please ensure you have proper authorization before checking IP addresses that don't belong to you.
