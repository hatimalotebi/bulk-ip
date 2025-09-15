"""
Ultra-Fast OTX Risk Checker
Gets only the essential risk information in seconds, not minutes.
"""

import os
import requests
from dotenv import load_dotenv
from colorama import init, Fore, Style

load_dotenv()
init(autoreset=True)

def quick_risk_check(ip: str) -> dict:
    """
    Ultra-fast risk check - only gets pulse count and basic info
    """
    api_key = os.getenv('OTX_API_KEY')
    if not api_key:
        return {"error": "No API key"}
    
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        # Only get general data (fastest endpoint)
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 404:
            return {
                "ip": ip,
                "risk": "CLEAN",
                "score": 0,
                "pulses": 0,
                "country": "Unknown"
            }
        
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            country = data.get("country_code", "Unknown")
            
            # Simple risk calculation
            if pulse_count >= 5:
                risk = "HIGH"
                score = 80
            elif pulse_count >= 2:
                risk = "MEDIUM" 
                score = 50
            elif pulse_count >= 1:
                risk = "LOW"
                score = 25
            else:
                risk = "CLEAN"
                score = 0
            
            # Country bonus
            if country in ['RU', 'CN', 'KP', 'IR']:
                score += 20
                if risk == "CLEAN":
                    risk = "LOW"
                elif risk == "LOW":
                    risk = "MEDIUM"
            
            return {
                "ip": ip,
                "risk": risk,
                "score": min(score, 100),
                "pulses": pulse_count,
                "country": country
            }
        else:
            return {"ip": ip, "error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def main():
    """Main function"""
    import sys
    
    print(f"{Fore.CYAN}⚡ Ultra-Fast OTX Risk Checker{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
    
    # Get IPs from command line or use examples
    if len(sys.argv) > 1:
        ips = sys.argv[1:]
    else:
        ips = ["92.63.197.59", "8.8.8.8", "1.1.1.1"]
        print(f"{Fore.YELLOW}Using example IPs{Style.RESET_ALL}")
    
    results = []
    
    for ip in ips:
        print(f"Checking {ip}...", end=" ")
        result = quick_risk_check(ip)
        results.append(result)
        
        if "error" in result:
            print(f"{Fore.RED}ERROR: {result['error']}{Style.RESET_ALL}")
        else:
            # Color code the risk
            risk_colors = {
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW, 
                "LOW": Fore.GREEN,
                "CLEAN": Fore.CYAN
            }
            color = risk_colors.get(result["risk"], Fore.WHITE)
            print(f"{color}{result['risk']} ({result['score']}/100) - {result['pulses']} pulses{Style.RESET_ALL}")
    
    # Summary
    print(f"\n{Fore.CYAN}📊 SUMMARY:{Style.RESET_ALL}")
    high_risk = [r for r in results if r.get("risk") in ["HIGH", "MEDIUM"]]
    if high_risk:
        print(f"{Fore.RED}⚠️  {len(high_risk)} IPs need attention:{Style.RESET_ALL}")
        for r in high_risk:
            print(f"  {r['ip']}: {r['risk']} ({r['score']}/100)")
    else:
        print(f"{Fore.GREEN}✅ All IPs are clean or low risk{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
