#!/usr/bin/env python3
"""
Bulk IP Threat Intelligence Checker - Auto Launcher
==================================================
Single Python file that handles everything automatically:
- Checks Python installation
- Installs dependencies
- Starts the Flask application
- Handles errors gracefully
"""

import sys
import subprocess
import os
import time
import webbrowser
from pathlib import Path

def print_header():
    """Print the application header"""
    print("=" * 60)
    print("    Bulk IP Threat Intelligence Checker")
    print("    Auto Launcher - One Click Setup & Run")
    print("=" * 60)
    print()

def print_step(step_num, total_steps, message):
    """Print a step with progress indicator"""
    print(f"[{step_num}/{total_steps}] {message}")

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""
    print(f"❌ {message}")

def print_warning(message):
    """Print warning message"""
    print(f"⚠️  {message}")

def print_info(message):
    """Print info message"""
    print(f"ℹ️  {message}")

def check_python_version():
    """Check if Python version is compatible"""
    print_step(1, 5, "Checking Python installation...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print_error("Python 3.7 or higher is required")
        print_info(f"Current version: {version.major}.{version.minor}.{version.micro}")
        print_warning("Please install Python 3.7+ from: https://www.python.org/downloads/")
        print_warning("Make sure to check 'Add Python to PATH' during installation")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print_success(f"Python {version.major}.{version.minor}.{version.micro} is installed")
    return True

def check_required_files():
    """Check if all required files exist"""
    print_step(2, 5, "Checking required files...")
    
    required_files = ["main.py", "requirements.txt"]
    missing_files = []
    
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print_error(f"Missing required files: {', '.join(missing_files)}")
        print_warning("Please make sure you're running this script from the correct directory")
        print_warning("The script should be in the same folder as main.py and requirements.txt")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print_success("All required files found")
    return True

def install_dependencies():
    """Install required Python packages"""
    print_step(3, 5, "Installing required libraries...")
    
    try:
        # Check if pip is available
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
        
        # Install requirements
        print_info("Installing packages from requirements.txt...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                               capture_output=True, text=True)
        
        if result.returncode == 0:
            print_success("All libraries installed successfully")
            return True
        else:
            print_error("Failed to install some libraries")
            print_warning("Error details:")
            print(result.stderr)
            print_warning("This might be due to:")
            print_warning("• No internet connection")
            print_warning("• Firewall blocking pip")
            print_warning("• Corrupted pip cache")
            print_warning("\nTry running as administrator or check your internet connection")
            input("\nPress Enter to exit...")
            sys.exit(1)
            
    except subprocess.CalledProcessError:
        print_error("pip is not available")
        print_warning("Please reinstall Python with pip included")
        input("\nPress Enter to exit...")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error during installation: {str(e)}")
        input("\nPress Enter to exit...")
        sys.exit(1)

def check_port_availability():
    """Check if port 5000 is available"""
    print_step(4, 5, "Checking port availability...")
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 5000))
        sock.close()
        
        if result == 0:
            print_warning("Port 5000 is already in use")
            print_info("This might be from a previous instance of the application")
            print_info("Trying to start anyway...")
        else:
            print_success("Port 5000 is available")
    except Exception:
        print_info("Could not check port availability, continuing...")

def start_application():
    """Start the Flask application"""
    print_step(5, 5, "Starting Bulk IP Checker...")
    
    print_success("Application starting...")
    print()
    print("=" * 60)
    print("    Application Information")
    print("=" * 60)
    print("🌐 Web Interface: http://127.0.0.1:5000")
    print("📊 Features: AbuseIPDB + VirusTotal + OTX")
    print("⚡ Performance: Optimized multi-threading")
    print("🛡️  Saudi Telecom: Whitelisted (no false positives)")
    print()
    print("⚠️  Press Ctrl+C to stop the application")
    print("=" * 60)
    print()
    
    # Wait a moment for user to read
    time.sleep(2)
    
    try:
        # Start the Flask application
        subprocess.run([sys.executable, "main.py"])
        
    except KeyboardInterrupt:
        print("\n")
        print_success("Application stopped by user")
    except Exception as e:
        print_error(f"Application failed to start: {str(e)}")
        print_warning("Common solutions:")
        print_warning("• Check if port 5000 is available")
        print_warning("• Run as administrator")
        print_warning("• Check Python installation")
        print_warning("• Verify all dependencies are installed")
        input("\nPress Enter to exit...")
        sys.exit(1)

def main():
    """Main function"""
    try:
        print_header()
        
        # Run all checks and setup
        check_python_version()
        check_required_files()
        install_dependencies()
        check_port_availability()
        start_application()
        
    except KeyboardInterrupt:
        print("\n")
        print_success("Setup interrupted by user")
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        print_warning("Please check the error details above")
        input("\nPress Enter to exit...")
        sys.exit(1)
    finally:
        print()
        print_success("Script execution completed")

if __name__ == "__main__":
    main()
