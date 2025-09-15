# 🛡️ Bulk IP Threat Intelligence Checker

A powerful web application for bulk checking IP addresses against multiple threat intelligence sources. Get comprehensive security analysis with **AbuseIPDB**, **VirusTotal**, and **OTX** data in seconds.

## ✨ Features

- **🔍 Triple Threat Intelligence**: AbuseIPDB + VirusTotal + OTX integration
- **⚡ Ultra-Fast Processing**: Multi-threaded bulk checking (20-100 concurrent threads)
- **💾 Smart Caching**: SQLite database prevents redundant API calls
- **📊 Rich Data Export**: CSV, Excel, and copy-to-clipboard functionality
- **🎯 High-Risk Detection**: Automatic flagging of malicious IPs
- **🌐 Modern Web UI**: Clean interface with real-time results
- **🛡️ Saudi Telecom Whitelist**: No false positives for legitimate Saudi ISPs

## 🚀 Quick Start (One-Click Setup)

### **Step 1: Install Python**
1. Download Python from: https://www.python.org/downloads/
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Restart your computer after installation

### **Step 2: Run the Application**
1. **Double-click** `run_bulk_ip_checker.py`
2. Wait for automatic setup to complete
3. Open your browser to: **http://127.0.0.1:5000**

That's it! The script will automatically:
- ✅ Check Python installation
- ✅ Install all required libraries
- ✅ Start the web application
- ✅ Handle any errors gracefully

## 🔑 API Keys Setup

### **1. AbuseIPDB API Key**
1. Go to: https://www.abuseipdb.com/register
2. Create a free account
3. Go to: https://www.abuseipdb.com/account/api
4. Copy your API key
5. Edit `main.py` and replace `YOUR_ABUSEIPDB_API_KEY` with your key

### **2. VirusTotal API Key**
1. Go to: https://www.virustotal.com/gui/join-us
2. Create a free account
3. Go to: https://www.virustotal.com/gui/my-apikey
4. Copy your API key
5. Edit `main.py` and replace `YOUR_VIRUSTOTAL_API_KEY` with your key

### **3. OTX API Key**
1. Go to: https://otx.alienvault.com/join
2. Create a free account
3. Go to: https://otx.alienvault.com/settings
4. Copy your API key
5. Edit `main.py` and replace `YOUR_OTX_API_KEY` with your key

## 📋 What You Get

### **Data Sources**
- **AbuseIPDB**: Primary threat intelligence with confidence scores
- **VirusTotal**: Malware detection and reputation analysis
- **OTX**: Open Threat Exchange with pulse information

### **Risk Assessment**
- **High Risk**: AbuseIPDB >80% OR VirusTotal ≥2 malicious OR OTX HIGH (non-Saudi)
- **Safe**: All other IPs (including Saudi telecom companies)

### **Export Options**
- **CSV Export**: Download results as CSV file
- **Excel Export**: Download results as Excel file
- **Copy to Clipboard**: Copy formatted data for Excel

## 🎯 How to Use

1. **Start the Application**: Double-click `run_bulk_ip_checker.py`
2. **Open Browser**: Go to http://127.0.0.1:5000
3. **Enter IPs**: Paste IP addresses (one per line or space-separated)
4. **Click Check**: Wait for results (usually 10-30 seconds)
5. **Review Results**: Check the main table and high-risk IPs
6. **Export Data**: Use export buttons for CSV/Excel

## ⚠️ Troubleshooting

### **"Python is not installed"**
- Download Python from: https://www.python.org/downloads/
- Make sure to check "Add Python to PATH" during installation
- Restart your computer after installation

### **"Failed to install libraries"**
- Check your internet connection
- Try running as administrator
- Make sure you're in the correct directory

### **"Port 5000 is already in use"**
- Close other applications using port 5000
- Or restart your computer

### **"Application failed to start"**
- Check if all API keys are set correctly
- Verify Python installation
- Try running as administrator

## 🔧 Manual Installation (Alternative)

If the auto-launcher doesn't work:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## 📊 Performance

- **Speed**: 20-100 concurrent threads for fast processing
- **Caching**: SQLite database prevents redundant API calls
- **Optimization**: Connection pooling and retry logic
- **Saudi Whitelist**: No false positives for legitimate Saudi ISPs

## 🛡️ Security Features

- **Saudi Telecom Whitelist**: Automatically whitelists legitimate Saudi ISPs
- **Conservative Risk Assessment**: Only flags truly malicious IPs
- **Multiple Data Sources**: Cross-references three threat intelligence APIs
- **Smart Caching**: Reduces API calls and improves performance

## 📞 Support

If you encounter any issues:
1. Check the error messages in the console
2. Verify all API keys are set correctly
3. Make sure Python is installed and in PATH
4. Try running as administrator
5. Check your internet connection

## 🎉 Ready to Start?

Just **double-click** `run_bulk_ip_checker.py` and you're ready to go!

---

**🌐 Web Interface**: http://127.0.0.1:5000  
**📧 Support**: Check error messages for troubleshooting  
**🔑 API Keys**: Follow the setup instructions above