import os
import subprocess
import sys
from pathlib import Path

def check_tool_installed(tool_name):
    """Check if a required tool is installed"""
    try:
        subprocess.run([tool_name, '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_nikto(target):
    """Run Nikto security scanner"""
    print("[+] Running Nikto (Security Misconfigurations)")
    try:
        subprocess.run(["nikto", "-h", target, "-o", "nikto_report.txt"], check=True)
        print("[+] Nikto scan completed.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Nikto scan failed: {e}")
    except FileNotFoundError:
        print("[-] Error: Nikto not installed or not found in PATH")

def run_sqlmap(target):
    """Run SQLmap for SQL injection testing"""
    print("[+] Running SQLmap (SQL Injection)")
    try:
        subprocess.run([
            "sqlmap", 
            "-u", target, 
            "--batch", 
            "--level=5", 
            "--risk=3", 
            "--output-dir=sqlmap_report"
        ], check=True)
        print("[+] SQLmap scan completed.")
    except subprocess.CalledProcessError as e:
        print(f"[-] SQLmap scan failed: {e}")
    except FileNotFoundError:
        print("[-] Error: SQLmap not installed or not found in PATH")

def run_nmap(target):
    """Run Nmap port scanning"""
    print("[+] Running Nmap (Open Ports & Misconfigurations)")
    try:
        subprocess.run([
            "nmap", 
            "-sV", 
            "-A", 
            target, 
            "-oN", 
            "nmap_report.txt"
        ], check=True)
        print("[+] Nmap scan completed.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap scan failed: {e}")
    except FileNotFoundError:
        print("[-] Error: Nmap not installed or not found in PATH")

def run_zap_scan(target):
    """Run OWASP ZAP security scanner"""
    print("[+] Running OWASP ZAP (XSS, SSRF, Injection)")
    try:
        subprocess.run([
            "zap-cli", 
            "quick-scan", 
            "--self-contained", 
            target
        ], check=True)
        print("[+] OWASP ZAP scan completed.")
    except subprocess.CalledProcessError as e:
        print(f"[-] ZAP scan failed: {e}")
    except FileNotFoundError:
        print("[-] Error: zap-cli not installed or not found in PATH")

def run_dependency_check(project_path):
    """Run OWASP Dependency Check"""
    print("[+] Running OWASP Dependency Check (Vulnerable Libraries)")
    try:
        subprocess.run([
            "dependency-check",
            "--scan", 
            project_path,
            "--format", "HTML",
            "--out", "dependency_report.html"
        ], check=True)
        print("[+] Dependency Check completed.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Dependency Check failed: {e}")
    except FileNotFoundError:
        print("[-] Error: dependency-check not installed or not found in PATH")

def main():
    """Main function to orchestrate security scans"""
    # Check for required tools
    required_tools = ["nikto", "sqlmap", "nmap", "zap-cli", "dependency-check"]
    missing_tools = [tool for tool in required_tools if not check_tool_installed(tool)]
    
    if missing_tools:
        print("[-] Error: The following tools are missing:")
        for tool in missing_tools:
            print(f"    - {tool}")
        print("Please install them before running the script.")
        sys.exit(1)

    # Get target information
    target = input("Enter the target URL/IP: ").strip()
    if not target:
        print("[-] Error: Target cannot be empty")
        sys.exit(1)

    # Get project path for dependency check
    project_path = input("Enter the project path for dependency check (or press Enter for default ./): ").strip()
    project_path = project_path if project_path else "./"
    
    if not Path(project_path).exists():
        print(f"[-] Error: Project path '{project_path}' does not exist")
        sys.exit(1)

    # Run security scans
    run_nikto(target)
    run_sqlmap(target)
    run_nmap(target)
    run_zap_scan(target)
    run_dependency_check(project_path)
    
    print("\n[+] Automated OWASP Top 10 scan completed. Check reports for details.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error occurred: {e}")
        sys.exit(1)
