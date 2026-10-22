import requests
import socket
from urllib.parse import urlparse

def scan_website_security(url):
    print(f"[+] Scanning started for: {url}")
    report = {"url": url, "vulnerabilities": [], "status": "Secure"}
    
    # 1. Parse URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    
    # 2. Check SSL/HTTPS (Encryption Layer)
    if not url.startswith("https://"):
        report["vulnerabilities"].append("High: Website is not using HTTPS. Data transmitted is not encrypted.")
        report["status"] = "Vulnerable"
        
    # 3. Check for Dangerous Open Ports (Common Hacking Entry Points)
    # Checking common ports: 21 (FTP), 22 (SSH), 23 (Telnet), 445 (SMB)
    ports_to_check = [21, 22, 23, 445]
    open_ports = []
    
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # Quick timeout
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
            
    if open_ports:
        report["vulnerabilities"].append(f"Critical: Dangerous open ports found: {open_ports}. Hackers can exploit these services.")
        report["status"] = "Vulnerable"

    # 4. Check for Basic Security Headers
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        if "X-Frame-Options" not in headers:
            report["vulnerabilities"].append("Medium: Missing X-Frame-Options header. Vulnerable to Clickjacking attacks.")
            report["status"] = "Vulnerable"
            
        if "Content-Security-Policy" not in headers:
            report["vulnerabilities"].append("Medium: Missing Content-Security-Policy (CSP) header. Vulnerable to XSS attacks.")
            report["status"] = "Vulnerable"
            
    except requests.exceptions.RequestException as e:
        report["vulnerabilities"].append(f"Error: Could not connect to website for header analysis. ({str(e)})")

    return report

# Example Usage:
if __name__ == "__main__":
    # Test with any website URL
    target_url = "http://example.com" 
    scan_result = scan_website_security(target_url)
    
    # Printing the professional automated report
    print("\n" + "="*50)
    print(f"MYCYBER AUTOMATED SECURITY REPORT")
    print("="*50)
    print(f"Target URL: {scan_result['url']}")
    print(f"Overall Status: {scan_result['status']}")
    print("-"*50)
    if scan_result["vulnerabilities"]:
        print("Vulnerabilities Found:")
        for vuln in scan_result["vulnerabilities"]:
            print(f" - {vuln}")
    else:
        print("[+] No basic vulnerabilities found. Looking good!")
    print("="*50)