#!/usr/bin/env python3
"""
Subdomain Validator
Checks: Live/Down status, A record, CNAME, MX, TXT, NS, and SSL certificate details
Usage:
    python3 subdomain_checker.py -f subdomains.txt  # from file (one per line)
    python3 subdomain_checker.py -d sub1.com sub2.com  # direct args
"""

import sys
import socket
import ssl
import datetime
import json
import argparse
import concurrent.futures
import io
import csv
from typing import Optional

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARN] dnspython not available, falling back to socket for DNS.")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─────────────────────────── ANSI Colors ────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA = "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}  ____  _                      _ _   ____        _     _             
 / ___|| | ___   _ / _/ __ _  | | | | __ )  __ _| |__ (_) ___  ___   
 \___ \| |/ / | | | |_ / _` | | | | |  _ \ / _` | '_ \| |/ _ \/ __|  
  ___) |   <| |_| |  _| (_| | | | | | |_) | (_| | |_) | |  __/\__ \  
 |____/|_|\_\\__, |_|  \__,_| |_|_| |____/ \__,_|_.__/|_|\___||___/  
             |___/                                                   {RESET}
{MAGENTA}{BOLD}          - Skyfall Babies Subdomain Validator -{RESET}
"""

def print_banner():
    print(BANNER)

# Handle Windows terminal encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, io.UnsupportedOperation):
        pass

# Fallback characters for environments that don't support Unicode
def get_char(char: str, fallback: str) -> str:
    try:
        char.encode(sys.stdout.encoding or 'ascii')
        return char
    except (UnicodeEncodeError, TypeError):
        return fallback

ICON_OK      = get_char("✔", "[+]")
ICON_ERR     = get_char("✘", "[-]")
ICON_WARN    = get_char("⚠", "[!]")
SEP_SINGLE   = get_char("─", "-")
SEP_DOUBLE   = get_char("═", "=")
DOT          = get_char("·", "|")
ARROW        = get_char("→", "->")

# ─────────────────────────── DNS Helpers ────────────────────────────

def resolve_record(domain: str, rtype: str) -> list[str]:
    """Return list of record values for given type, empty list on failure."""
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        if rtype == "MX":
            return [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
        elif rtype == "SOA":
            r = answers[0]
            return [f"mname={r.mname.to_text().rstrip('.')} serial={r.serial}"]
        else:
            return [r.to_text().rstrip('"').strip('"') for r in answers]
    except Exception:
        return []


def get_a_record(domain: str) -> list[str]:
    records = resolve_record(domain, "A")
    if not records:
        try:
            ip = socket.gethostbyname(domain)
            records = [ip]
        except Exception:
            pass
    return records


def get_aaaa_record(domain: str) -> list[str]:
    return resolve_record(domain, "AAAA")


def get_cname(domain: str) -> list[str]:
    return resolve_record(domain, "CNAME")


def get_mx(domain: str) -> list[str]:
    return resolve_record(domain, "MX")


def get_ns(domain: str) -> list[str]:
    return resolve_record(domain, "NS")


def get_txt(domain: str) -> list[str]:
    return resolve_record(domain, "TXT")


# ─────────────────────────── HTTP Check ─────────────────────────────

def check_http(domain: str, timeout: int = 6) -> dict:
    result = {"live": False, "status_code": None, "redirect": None, "http_live": False, "https_live": False, "server": None}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            if REQUESTS_AVAILABLE:
                r = requests.get(url, timeout=timeout, verify=False,
                                 allow_redirects=True,
                                 headers={"User-Agent": "SubdomainChecker/1.0"})
                result[f"{scheme}_live"] = True
                result["live"] = True
                result["status_code"] = r.status_code
                result["server"] = r.headers.get("Server", "")
                if r.url != url:
                    result["redirect"] = r.url
                break
            else:
                import urllib.request
                req = urllib.request.Request(url, headers={"User-Agent": "SubdomainChecker/1.0"})
                resp = urllib.request.urlopen(req, timeout=timeout)
                result[f"{scheme}_live"] = True
                result["live"] = True
                result["status_code"] = resp.status
                break
        except Exception:
            continue
    return result


# ─────────────────────────── SSL Check ──────────────────────────────

def check_ssl(domain: str, port: int = 443, timeout: int = 6) -> dict:
    result = {
        "ssl_valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "san": [],
        "ssl_version": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["ssl_valid"] = True
                result["ssl_version"] = ssock.version()

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

                # Subject / CN
                subject = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subject.get("commonName", "Unknown")

                # Validity dates
                fmt = "%b %d %H:%M:%S %Y %Z"
                nb = cert.get("notBefore", "")
                na = cert.get("notAfter", "")
                if nb:
                    result["not_before"] = datetime.datetime.strptime(nb, fmt).strftime("%Y-%m-%d")
                if na:
                    exp = datetime.datetime.strptime(na, fmt)
                    result["not_after"] = exp.strftime("%Y-%m-%d")
                    result["days_remaining"] = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days

                # SANs
                sans = []
                for stype, sval in cert.get("subjectAltName", []):
                    if stype == "DNS":
                        sans.append(sval)
                result["san"] = sans
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Cert verification failed: {e}"
        # Still try to grab cert info without verification
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
        except Exception:
            pass
    except ConnectionRefusedError:
        result["error"] = "Port 443 refused"
    except socket.timeout:
        result["error"] = "SSL connection timed out"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


# ─────────────────────────── Full Check ─────────────────────────────

def check_subdomain(domain: str) -> dict:
    domain = domain.strip().lower()
    result = {"domain": domain}

    # DNS
    result["a_records"]    = get_a_record(domain)
    result["aaaa_records"] = get_aaaa_record(domain)
    result["cname"]        = get_cname(domain)
    result["mx"]           = get_mx(domain)
    result["ns"]           = get_ns(domain)
    result["txt"]          = get_txt(domain)

    # Determine if DNS resolves at all
    result["dns_resolves"] = bool(result["a_records"] or result["aaaa_records"] or result["cname"])

    # HTTP/HTTPS
    http_info = check_http(domain)
    result.update(http_info)

    # SSL
    ssl_info = check_ssl(domain)
    result["ssl"] = ssl_info

    return result


# ─────────────────────────── Pretty Print ───────────────────────────

def status_icon(ok: bool) -> str:
    return f"{GREEN}{ICON_OK}{RESET}" if ok else f"{RED}{ICON_ERR}{RESET}"


def days_color(days: Optional[int]) -> str:
    if days is None:
        return f"{DIM}N/A{RESET}"
    if days < 0:
        return f"{RED}{days}d EXPIRED{RESET}"
    if days < 15:
        return f"{RED}{days}d{RESET}"
    if days < 30:
        return f"{YELLOW}{days}d{RESET}"
    return f"{GREEN}{days}d{RESET}"


def print_result(r: dict):
    d = r["domain"]
    live = r.get("live", False)
    dns_ok = r.get("dns_resolves", False)
    ssl = r.get("ssl", {})

    # Header line
    live_str = f"{GREEN}{BOLD}LIVE{RESET}" if live else (f"{YELLOW}DNS-ONLY{RESET}" if dns_ok else f"{RED}DOWN{RESET}")
    print(f"\n{SEP_SINGLE*62}")
    print(f"  {BOLD}{CYAN}{d}{RESET}   [{live_str}]")
    print(f"{SEP_SINGLE*62}")

    # HTTP
    code = r.get("status_code")
    code_str = f"{GREEN}{code}{RESET}" if code and 200 <= code < 400 else (f"{RED}{code}{RESET}" if code else f"{DIM}—{RESET}")
    print(f"  {BOLD}HTTP{RESET}      {status_icon(live)}  HTTPS:{status_icon(r.get('https_live',False))}  HTTP:{status_icon(r.get('http_live',False))}  Status:{code_str}", end="")
    if r.get("server"):
        print(f"  Server:{DIM}{r['server']}{RESET}", end="")
    if r.get("redirect"):
        print(f"  {ARROW} {DIM}{r['redirect']}{RESET}", end="")
    print()

    # DNS
    print(f"  {BOLD}DNS{RESET}       {status_icon(dns_ok)}")
    if r["a_records"]:
        print(f"    A       : {', '.join(r['a_records'])}")
    if r["aaaa_records"]:
        print(f"    AAAA    : {', '.join(r['aaaa_records'])}")
    if r["cname"]:
        print(f"    CNAME   : {YELLOW}{', '.join(r['cname'])}{RESET}")
    if r["mx"]:
        print(f"    MX      : {', '.join(r['mx'][:3])}")
    if r["ns"]:
        print(f"    NS      : {', '.join(r['ns'][:3])}")
    if r["txt"]:
        for t in r["txt"][:3]:
            print(f"    TXT     : {DIM}{t[:80]}{RESET}")

    if not dns_ok:
        print(f"    {RED}No DNS records found — domain may not exist or has no resolution{RESET}")

    # SSL
    s = ssl
    ssl_ok = s.get("ssl_valid", False)
    print(f"  {BOLD}SSL{RESET}       {status_icon(ssl_ok)}", end="")
    if ssl_ok:
        print(f"  {s.get('ssl_version','')}", end="")
    print()
    if ssl_ok:
        print(f"    Subject : {s.get('subject','')}")
        print(f"    Issuer  : {s.get('issuer','')}")
        print(f"    Valid   : {s.get('not_before','')} → {s.get('not_after','')}")
        print(f"    Expiry  : {days_color(s.get('days_remaining'))}")
        if s.get("san"):
            san_preview = s["san"][:4]
            extra = len(s["san"]) - 4
            print(f"    SANs    : {', '.join(san_preview)}" + (f" +{extra} more" if extra > 0 else ""))
    elif s.get("error"):
        print(f"    {RED}{s['error']}{RESET}")


def print_summary(results: list[dict]):
    total = len(results)
    live  = sum(1 for r in results if r.get("live"))
    dns   = sum(1 for r in results if r.get("dns_resolves") and not r.get("live"))
    down  = total - live - dns
    ssl_ok = sum(1 for r in results if r.get("ssl", {}).get("ssl_valid"))
    exp_soon = sum(1 for r in results if 0 <= (r.get("ssl", {}).get("days_remaining") or 999) < 30)

    print(f"\n{SEP_DOUBLE*62}")
    print(f"  {BOLD}SUMMARY{RESET}  ({total} subdomains scanned)")
    print(f"{SEP_DOUBLE*62}")
    print(f"  {GREEN}{ICON_OK} Live (HTTP reachable){RESET}    : {live}")
    print(f"  {YELLOW}~ DNS resolves, not HTTP{RESET}  : {dns}")
    print(f"  {RED}{ICON_ERR} Down / No DNS{RESET}           : {down}")
    print(f"  {GREEN}{ICON_OK} Valid SSL{RESET}               : {ssl_ok}")
    if exp_soon:
        print(f"  {YELLOW}{ICON_WARN} SSL expiring <30 days{RESET}   : {exp_soon}")
    print(f"{SEP_DOUBLE*62}\n")


def save_json(results: list[dict], path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"  {DIM}JSON report saved {ARROW} {path}{RESET}")


def save_csv(results: list[dict], path: str):
    headers = [
        "Domain", "A Records", "Service", "IPv6 (AAAA)", "CNAME", 
        "SSL Check", "Subject", "SANs", "Remark", "Status"
    ]
    
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        for r in results:
            ssl = r.get("ssl", {})
            
            # Service logic
            services = []
            if r.get("https_live"): services.append("HTTPS")
            if r.get("http_live"): services.append("HTTP")
            service_str = ", ".join(services) if services else "None"
            
            # SSL logic
            ssl_status = "Valid" if ssl.get("ssl_valid") else (f"Error: {ssl.get('error')}" if ssl.get("error") else "N/A")
            
            # Status logic
            status = "Live" if r.get("live") else ("DNS-ONLY" if r.get("dns_resolves") else "Down")
            
            # Remark logic
            remarks = []
            if r.get("redirect"): remarks.append(f"Redirects to {r['redirect']}")
            if r.get("server"): remarks.append(f"Server: {r['server']}")
            if not r.get("dns_resolves"): remarks.append("No DNS resolution")
            remark_str = "; ".join(remarks)
            
            writer.writerow({
                "Domain": r["domain"],
                "A Records": ", ".join(r.get("a_records", [])),
                "Service": service_str,
                "IPv6 (AAAA)": ", ".join(r.get("aaaa_records", [])),
                "CNAME": ", ".join(r.get("cname", [])),
                "SSL Check": ssl_status,
                "Subject": ssl.get("subject", ""),
                "SANs": ", ".join(ssl.get("san", [])),
                "Remark": remark_str,
                "Status": status
            })
    print(f"  {DIM}CSV report saved  {ARROW} {path}{RESET}\n")


# ─────────────────────────── Entry Point ────────────────────────────

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Subdomain Validator — DNS, CNAME, A, MX, NS, TXT, SSL")
    parser.add_argument("-f", "--file", help="Text file with one subdomain per line")
    parser.add_argument("-d", "--domains", nargs="+", help="Subdomains to check directly")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Parallel threads (default: 10)")
    parser.add_argument("-o", "--output", help="Base name for output files (e.g., report)")
    args = parser.parse_args()

    domains = []
    if args.file:
        file_path = args.file
    elif args.domains:
        domains = args.domains
        file_path = None
    else:
        # Interactive fallback if no args
        print(f"{YELLOW}{ICON_WARN} No input domains provided.{RESET}")
        file_path = input(f"  {BOLD}Enter path to subdomain file:{RESET} ").strip()
        if not file_path:
            print(f"{RED}No file path entered. Exiting.{RESET}")
            sys.exit(0)

    if file_path:
        try:
            with open(file_path) as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"{RED}File not found: {file_path}{RESET}")
            sys.exit(1)

    domains = list(dict.fromkeys(d for d in domains if d))  # deduplicate

    print(f"\n{BOLD}{SEP_DOUBLE*62}")
    print(f"  Subdomain Validator  {DOT}  {len(domains)} domains  {DOT}  {args.threads} threads")
    print(f"{SEP_DOUBLE*62}{RESET}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(check_subdomain, d): d for d in domains}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            print(f"  {DIM}[{done}/{len(domains)}] Scanning {futures[future]}...{RESET}", end="\r")
            try:
                result = future.result()
                results.append(result)
                print_result(result)
            except Exception as e:
                print(f"\n  {RED}Error on {futures[future]}: {e}{RESET}")

    # Sort: live first, then dns-only, then down
    results.sort(key=lambda r: (0 if r.get("live") else 1 if r.get("dns_resolves") else 2, r["domain"]))

    print_summary(results)
    
    output_base = args.output if args.output else f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_json(results, f"{output_base}.json")
    save_csv(results, f"{output_base}.csv")


if __name__ == "__main__":
    main()