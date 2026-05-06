#!/usr/bin/env python3
"""
SKYFALL BABIES - Unified Cybersecurity Automation Platform
Master Entry Point for MCP Server and Recon Tools
"""

import os
import sys
import subprocess
import time
from typing import List

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
PROJECT_NAME = "SKYFALL BABIES"

# Colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA = "\033[95m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
{CYAN}{BOLD}
  ____  _                      _ _   ____        _     _             
 / ___|| | ___   _ / _/ __ _  | | | | __ )  __ _| |__ (_) ___  ___   
 \___ \| |/ / | | | |_ / _` | | | | |  _ \ / _` | '_ \| |/ _ \/ __|  
  ___) |   <| |_| |  _| (_| | | | | | |_) | (_| | |_) | |  __/\__ \  
 |____/|_|\_\\__, |_|  \__,_| |_|_| |____/ \__,_|_.__/|_|\___||___/  
             |___/                                                   
{RESET}
{MAGENTA}{BOLD}          - Unified Cybersecurity Automation Platform -{RESET}
{YELLOW}                    Version: {VERSION} | By: Skyfall{RESET}
{CYAN}{'═' * 70}{RESET}
"""
    print(banner)

def print_menu():
    print(f"{BOLD}[ Main Menu ]{RESET}\n")
    print(f"{GREEN}1.{RESET} {BOLD}Launch MCP Kali Server{RESET} (Advanced API Bridge)")
    print(f"{GREEN}2.{RESET} {BOLD}Subdomain Validator{RESET} (DNS, SSL, HTTP Analysis)")
    print(f"{GREEN}3.{RESET} {BOLD}Domain Status Checker{RESET} (Bulk HTTP/HTTPS Status)")
    print(f"{GREEN}4.{RESET} {BOLD}Setup / Install Dependencies{RESET}")
    print(f"{GREEN}5.{RESET} {BOLD}Cleanup Workspace{RESET}")
    print(f"{RED}0.{RESET} {BOLD}Exit{RESET}\n")

# ─────────────────────────────────────────────────────────────────────────────
# TOOL LAUNCHERS
# ─────────────────────────────────────────────────────────────────────────────

def run_script(path: str, args: List[str] = []):
    """Run a python script in a separate process"""
    if not os.path.exists(path):
        print(f"{RED}[!] Error: File not found at {path}{RESET}")
        input("\nPress Enter to continue...")
        return
    
    try:
        cmd = [sys.executable, path] + args
        print(f"{YELLOW}[*] Launching: {' '.join(cmd)}{RESET}\n")
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Process interrupted.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error launching script: {e}{RESET}")
    
    input("\nPress Enter to return to menu...")

def setup_environment():
    """Install required dependencies"""
    print(f"{YELLOW}[*] Installing dependencies...{RESET}")
    try:
        # Define common requirements
        reqs = ["flask", "requests", "python-dotenv", "psutil", "pandas", "dnspython", "openpyxl"]
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + reqs)
        print(f"\n{GREEN}[+] All dependencies installed successfully!{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Error during installation: {e}{RESET}")
    
    input("\nPress Enter to return to menu...")

def cleanup_workspace():
    """Remove unwanted/temporary files"""
    print(f"{YELLOW}[*] Cleaning up workspace...{RESET}")
    
    # Files to remove
    unwanted_files = [
        "server_enhanced.py",
        "README_v7.md",
        "domain_status_results.csv",
        "domain_status_results_live.csv",
        "domain_status_results_not_live.csv",
        "domain_status_results_redirection.csv"
    ]
    
    # Also remove scan_report_*.csv/json
    count = 0
    
    # Search in current and tools directories
    dirs_to_check = [".", "tools"]
    
    for d in dirs_to_check:
        if not os.path.exists(d): continue
        for f in os.listdir(d):
            full_path = os.path.join(d, f)
            should_delete = False
            
            if f in unwanted_files:
                should_delete = True
            elif f.startswith("scan_report_") and (f.endswith(".csv") or f.endswith(".json")):
                should_delete = True
            
            if should_delete:
                try:
                    os.remove(full_path)
                    print(f"{DIM}[-] Deleted: {full_path}{RESET}")
                    count += 1
                except Exception as e:
                    print(f"{RED}[!] Could not delete {full_path}: {e}{RESET}")
    
    print(f"\n{GREEN}[+] Cleanup complete. {count} files removed.{RESET}")
    input("\nPress Enter to return to menu...")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        try:
            choice = input(f"{CYAN}{BOLD}Select an option > {RESET}").strip()
            
            if choice == "1":
                run_script("skyfall_server.py")
            elif choice == "2":
                run_script("tools/subdomainchecker.py")
            elif choice == "3":
                run_script("tools/statueschecker.py")
            elif choice == "4":
                setup_environment()
            elif choice == "5":
                cleanup_workspace()
            elif choice == "0" or choice.lower() == "exit":
                print(f"\n{GREEN}Goodbye! Stay safe.{RESET}")
                break
            else:
                print(f"\n{RED}[!] Invalid choice. Try again.{RESET}")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{GREEN}Goodbye! Stay safe.{RESET}")
            break

if __name__ == "__main__":
    main()
