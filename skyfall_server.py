#!/usr/bin/env python3
"""
Skyfall AI MCP Server v7.0 - Advanced Cybersecurity Automation Platform
Enhanced with authentication, dynamic tool registry, caching, and process management
"""

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import traceback
import threading
import psutil
import requests
from functools import wraps
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# Import new v7.0 modules
# Import core modules
from core.auth_manager import AuthenticationManager
from core.tool_registry import ToolRegistry
from core.cache_manager import LRUCache
from core.process_manager import ProcessManager
from core.decision_engine import IntelligentDecisionEngine
from core.ai_backend import AIBackend
from core.history_manager import HistoryManager
from core.notifier import Notifier
from core.reporter import Reporter

# Load environment variables
load_dotenv()

# Configuration
API_PORT = int(os.environ.get("SKYFALL_PORT", 8888))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 300))
AUTH_ENABLED = os.environ.get("SKYFALL_AUTH_ENABLED", "false").lower() in ("1", "true", "yes", "y")
CACHE_SIZE = int(os.environ.get("SKYFALL_CACHE_SIZE", 1000))
CACHE_TTL = int(os.environ.get("SKYFALL_CACHE_TTL", 3600))
AUTO_INSTALL_ENABLED = os.environ.get("SKYFALL_ENABLE_AUTO_INSTALL", "false").lower() in ("1", "true", "yes", "y")

# ANSI Colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA = "\033[95m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def normalize_target(target: str) -> Dict[str, str]:
    """Normalize target into URL + host forms for tool compatibility."""
    raw = (target or "").strip()
    if not raw:
        return {"raw": "", "url": "", "host": ""}

    # Accept host-only input and convert into URL for web tools.
    candidate_url = raw if re.match(r"^https?://", raw, re.IGNORECASE) else f"https://{raw}"
    parsed = urlparse(candidate_url)
    host = parsed.netloc or parsed.path

    # Remove optional auth/port for domain-oriented tools.
    host = host.split("@")[-1].split(":")[0]
    return {"raw": raw, "url": candidate_url, "host": host}


def get_tool_command(tool_name: str, target_url: str, target_host: str, scan_profile: str = "balanced") -> str:
    """Build command per tool using tuned defaults."""
    deep_nuclei = "-severity critical,high,medium,low"
    balanced_nuclei = "-severity critical,high,medium"
    nuclei_severity = deep_nuclei if scan_profile == "deep" else balanced_nuclei

    # Define tool command map
    command_map = {
        "nmap": f"nmap -sV -T4 -Pn {target_host}",
        "rustscan": f"rustscan -a {target_host} --ulimit 5000 -- -sV",
        "masscan": f"masscan {target_host} -p1-1000 --rate 2000",
        "amass": f"amass enum -passive -d {target_host}",
        "subfinder": f"subfinder -silent -d {target_host}",
        "dnsenum": f"dnsenum {target_host}",
        "fierce": f"fierce --domain {target_host}",
        "theHarvester": f"theHarvester -d {target_host} -b all -l 100",
        "nuclei": f"nuclei -u {target_url} {nuclei_severity} -rl 50 -c 25 -timeout 8 -retries 1",
        "gobuster": f"gobuster dir -u {target_url} -w {{WORDLIST}} -t 40 --timeout 5s --no-error",
        "httpx": f"httpx -silent -status-code -title -web-server -tech-detect -u {target_url}",
        "whatweb": f"whatweb -a 3 {target_url}",
        "nikto": f"nikto -h {target_url}",
        "ffuf": f"ffuf -u {target_url.rstrip('/')}/FUZZ -w {{WORDLIST}} -mc all -c -ac -t 40",
        "testssl": f"testssl --fast {target_host}",
        "wafw00f": f"wafw00f {target_url}",
        "waybackurls": f"echo {target_host} | waybackurls",
        "gau": f"gau {target_host}",
        "sqlmap": f"sqlmap -u {target_url} --batch --random-agent --level " + ("3" if scan_profile == "deep" else "1"),
        "dalfox": f"dalfox url {target_url} --no-color --timeout 10",
        "commix": f"commix --url {target_url} --batch --level 3",
        "enum4linux": f"enum4linux -a {target_host}",
        "crackmapexec": f"crackmapexec smb {target_host}",
    }
    
    cmd = command_map.get(tool_name, f"{tool_name} {target_url}")
    
    # Override with custom path if provided in env (e.g. NMAP_PATH, GOBUSTER_PATH)
    binary_name = tool_name.split()[0]
    env_path_key = f"{binary_name.upper()}_PATH"
    custom_path = os.environ.get(env_path_key)
    if custom_path:
        cmd = cmd.replace(binary_name, custom_path, 1)

    
    # Add proxy arguments
    proxy_args = proxy_manager.get_proxy_args(tool_name)
    if proxy_args:
        cmd += " " + " ".join(proxy_args)
        
    return cmd


def get_tool_timeout(tool_name: str, scan_profile: str = "balanced") -> int:
    base = {
        "httpx": 60, "subfinder": 90, "gobuster": 120, "nuclei": 120, "nmap": 180, "amass": 180,
        "whatweb": 120, "nikto": 240, "ffuf": 180, "testssl": 180, "wafw00f": 90, "waybackurls": 90,
        "gau": 90, "dnsenum": 180, "theHarvester": 180, "fierce": 180, "rustscan": 120, "masscan": 120
    }
    timeout = base.get(tool_name, 120)
    if scan_profile == "fast":
        return max(45, int(timeout * 0.7))
    if scan_profile == "deep":
        return int(timeout * 1.5)
    return timeout


WINGET_ID_MAP = {
    "nmap": "Insecure.Nmap",
    "sqlmap": "sqlmapproject.sqlmap",
    "gobuster": "OJ.Gobuster",
    "httpx": "projectdiscovery.httpx",
    "nuclei": "projectdiscovery.nuclei",
    "subfinder": "projectdiscovery.subfinder",
    "amass": "OWASP.Amass",
    "ffuf": "ffuf.ffuf",
    "nikto": "sullo.nikto",
}

APT_TOOL_MAP = {
    "nmap": "nmap", "amass": "amass", "subfinder": "subfinder", "gobuster": "gobuster", "httpx": "httpx-toolkit",
    "nuclei": "nuclei", "nikto": "nikto", "whatweb": "whatweb", "ffuf": "ffuf", "testssl": "testssl.sh",
    "wafw00f": "wafw00f", "theHarvester": "theharvester", "dnsenum": "dnsenum", "fierce": "fierce",
    "rustscan": "rustscan", "masscan": "masscan", "sqlmap": "sqlmap", "commix": "commix",
    "enum4linux": "enum4linux", "crackmapexec": "crackmapexec"
}

GITHUB_INSTALL_MAP = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}

WORDLIST_DIR = Path("data/wordlists")
DEFAULT_WORDLIST_PATH = "/usr/share/wordlists/dirb/common.txt" if os.name != 'nt' else str(Path("data/wordlists/common.txt"))
GITHUB_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"


def ensure_wordlist() -> str:
    """Return a usable wordlist path, downloading one if needed."""
    if os.path.exists(DEFAULT_WORDLIST_PATH):
        return DEFAULT_WORDLIST_PATH

    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    local_wordlist = WORDLIST_DIR / "common.txt"
    if local_wordlist.exists():
        return str(local_wordlist)

    try:
        resp = requests.get(GITHUB_WORDLIST_URL, timeout=30)
        resp.raise_for_status()
        local_wordlist.write_text(resp.text)
        logger.info(f"Downloaded fallback wordlist: {local_wordlist}")
        return str(local_wordlist)
    except Exception as e:
        logger.warning(f"Failed to download fallback wordlist: {e}")
        return DEFAULT_WORDLIST_PATH



def ensure_tool_available(tool_name: str, allow_install: bool = False) -> Dict[str, Any]:
    """Check tool availability, optionally install if allowed."""
    binary_name = tool_name.split()[0]
    
    # Check if a custom path is provided in environment variables
    env_path_key = f"{binary_name.upper()}_PATH"
    custom_path = os.environ.get(env_path_key)
    if custom_path and os.path.exists(custom_path):
        return {"tool": tool_name, "available": True, "installed": False, "method": "custom_path", "path": custom_path}

    if shutil.which(binary_name):
        return {"tool": tool_name, "available": True, "installed": False, "method": "existing"}
    
    # Fallback for common Linux paths if not in PATH (important for some container setups)
    common_paths = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"]
    for p in common_paths:
        full_p = os.path.join(p, binary_name)
        if os.path.exists(full_p):
            return {"tool": tool_name, "available": True, "installed": False, "method": "common_path", "path": full_p}

    if not allow_install or not AUTO_INSTALL_ENABLED:

        return {"tool": tool_name, "available": False, "installed": False, "reason": "missing"}

    install_errors = []
    
    # Try Windows Installation (winget)
    if os.name == 'nt':
        winget_id = WINGET_ID_MAP.get(tool_name)
        if winget_id:
            logger.info(f"Attempting to install {tool_name} via winget...")
            winget_cmd = f"winget install -e --id {winget_id} --accept-package-agreements --accept-source-agreements"
            result = CommandExecutor(winget_cmd, timeout=600).execute()
            if result.get("success") or shutil.which(binary_name):
                return {"tool": tool_name, "available": True, "installed": True, "method": "winget"}
            install_errors.append(result.get("stderr", "winget install failed"))

    # Try Linux Installation (apt)
    apt_pkg = APT_TOOL_MAP.get(tool_name)
    if apt_pkg and os.name != 'nt':
        apt_cmd = f"apt-get update && apt-get install -y {apt_pkg}"
        if os.geteuid() != 0:
            apt_cmd = f"sudo {apt_cmd}"
        result = CommandExecutor(apt_cmd, timeout=600).execute()
        if result.get("success") and shutil.which(binary_name):
            return {"tool": tool_name, "available": True, "installed": True, "method": "apt"}
        install_errors.append(result.get("stderr", "apt install failed"))

    # Try Go Installation
    gh_pkg = GITHUB_INSTALL_MAP.get(tool_name)
    if gh_pkg:
        go_cmd = f"go install {gh_pkg}"
        result = CommandExecutor(go_cmd, timeout=600).execute()
        if result.get("success"):
            go_bin = os.path.expanduser(f"~/go/bin/{binary_name}")
            if os.name == 'nt':
                go_bin = os.path.expanduser(f"~/go/bin/{binary_name}.exe")
            if os.path.exists(go_bin) or shutil.which(binary_name):
                return {"tool": tool_name, "available": True, "installed": True, "method": "github-go-install"}
        install_errors.append(result.get("stderr", "github install failed"))

    return {"tool": tool_name, "available": False, "installed": False, "reason": "install_failed", "errors": install_errors[:2]}


# Initialize Flask app
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

from core.mission_manager import MissionManager

# Initialize core managers
auth_manager = AuthenticationManager(enabled=AUTH_ENABLED)
tool_registry = ToolRegistry()
cache_manager = LRUCache(max_size=CACHE_SIZE, ttl_seconds=CACHE_TTL)
process_manager = ProcessManager()
decision_engine = IntelligentDecisionEngine(tool_registry)
ai_backend = AIBackend()
history_manager = HistoryManager()
from core.proxy_manager import ProxyManager
mission_manager = MissionManager()
proxy_manager = ProxyManager()
notifier = Notifier()
reporter = Reporter()

# Define Banner
BANNER = rf"""
{CYAN}  ____  _                      _ _   ____        _     _             
 / ___|| | ___   _ / _/ __ _  | | | | __ )  __ _| |__ (_) ___  ___   
 \___ \| |/ / | | | |_ / _` | | | | |  _ \ / _` | '_ \| |/ _ \/ __|  
  ___) |   <| |_| |  _| (_| | | | | | |_) | (_| | |_) | |  __/\__ \  
 |____/|_|\_\\__, |_|  \__,_| |_|_| |____/ \__,_|_.__/|_|\___||___/  
             |___/                                                   {RESET}
{MAGENTA}          - Skyfall AI Agents v7.0 -{RESET}
{YELLOW}     [ Intelligent Decision Engine | 150+ Tools | Stealth Browser ]{RESET}
"""

def print_banner():
    """Print the startup banner to console"""
    print(BANNER)
    logger.info("=" * 80)
    logger.info("Skyfall AI Agents v7.0 - Advanced Cybersecurity Automation Platform")
    logger.info(f"Port: {API_PORT} | Auth: {AUTH_ENABLED} | Tools: {len(tool_registry.tools)}")
    logger.info("=" * 80)


# ═════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION MIDDLEWARE
# ═════════════════════════════════════════════════════════════════════════════

def require_auth(f):
    """Decorator to require authentication on endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        
        # Public endpoints that don't require auth
        public_endpoints = ["/health", "/api/telemetry"]
        if request.path in public_endpoints:
            return f(*args, **kwargs)
        
        auth_header = request.headers.get("Authorization", "")
        if not auth_manager.verify_header(auth_header):
            return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


# ═════════════════════════════════════════════════════════════════════════════
# COMMAND EXECUTION ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class CommandExecutor:
    """Execute commands with timeout, streaming, and error handling"""
    
    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.use_shell = isinstance(command, str)
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False
    
    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing: {self.command}")
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            try:
                self.stdout_data, self.stderr_data = self.process.communicate(
                    timeout=self.timeout
                )
                self.return_code = self.process.returncode
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timeout after {self.timeout}s")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.return_code = -1
            
            success = self.return_code == 0 if not self.timed_out else bool(self.stdout_data)
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data)
            }
        except Exception as e:
            logger.error(f"Execution error: {e}\n{traceback.format_exc()}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error: {str(e)}",
                "return_code": -1,
                "success": False,
                "timed_out": False
            }


# ═════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Get authentication status"""
    return jsonify(auth_manager.get_status())


@app.route("/api/auth/generate-key", methods=["POST"])
@require_auth
def generate_api_key():
    """Generate new API key"""
    if not AUTH_ENABLED:
        return jsonify({"error": "Authentication is disabled"}), 400
    
    data = request.json or {}
    key_name = data.get("name", f"Key-{datetime.now().isoformat()}")
    
    key_id, key_secret = auth_manager.generate_key(key_name)
    
    return jsonify({
        "key_id": key_id,
        "key_secret": key_secret,
        "name": key_name,
        "note": "Save this secret securely - you won't see it again",
        "usage": f"Authorization: Bearer {key_id}:{key_secret}"
    })


@app.route("/api/auth/keys", methods=["GET"])
@require_auth
def list_api_keys():
    """List all API keys (secrets masked)"""
    if not AUTH_ENABLED:
        return jsonify({"error": "Authentication is disabled"}), 400
    
    return jsonify({"keys": auth_manager.list_keys(mask_secrets=True)})


@app.route("/api/auth/keys/<key_id>", methods=["DELETE"])
@require_auth
def revoke_api_key(key_id):
    """Revoke an API key"""
    if not AUTH_ENABLED:
        return jsonify({"error": "Authentication is disabled"}), 400
    
    if auth_manager.revoke_key(key_id):
        return jsonify({"message": f"Key {key_id} revoked"})
    return jsonify({"error": "Key not found"}), 404


# ═════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/tools/list", methods=["GET"])
@require_auth
def list_tools():
    """List all available tools"""
    category = request.args.get("category")
    return jsonify({"tools": tool_registry.list_tools(category)})


@app.route("/api/tools/categories", methods=["GET"])
@require_auth
def get_tool_categories():
    """Get tools organized by category"""
    return jsonify(tool_registry.get_categories())


@app.route("/api/tools/<tool_name>", methods=["GET"])
@require_auth
def get_tool_info(tool_name):
    """Get detailed information about a tool"""
    info = tool_registry.get_tool_info(tool_name)
    if info:
        return jsonify(info)
    return jsonify({"error": "Tool not found"}), 404


@app.route("/api/tools/availability", methods=["GET"])
@require_auth
def get_tool_availability():
    """Get tool availability statistics"""
    return jsonify(tool_registry.get_availability_stats())


# ═════════════════════════════════════════════════════════════════════════════
# DYNAMIC TOOL EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/execute", methods=["POST"])
@require_auth
def execute_tool():
    """Execute tool dynamically with parameters"""
    try:
        data = request.json or {}
        tool_name = data.get("tool_name", "")
        parameters = data.get("parameters", {})
        use_cache = data.get("use_cache", True)
        
        if not tool_name:
            return jsonify({"error": "tool_name is required"}), 400
        
        tool = tool_registry.get_tool(tool_name)
        if not tool:
            return jsonify({"error": f"Tool '{tool_name}' not found"}), 404
        
        # Check cache
        cache_key = f"tool:{tool_name}"
        if use_cache:
            cached_result = cache_manager.get(cache_key, parameters)
            if cached_result:
                return jsonify({"result": cached_result, "cached": True})
        
        # Build command
        command = [tool.command] + [str(v) for v in parameters.values()]
        
        # Execute
        executor = CommandExecutor(command)
        result = executor.execute()
        
        # Cache result
        if result.get("success") and use_cache:
            cache_manager.set(cache_key, result, parameters)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return jsonify({"error": str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════════
# PROCESS MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/processes/list", methods=["GET"])
@require_auth
def list_processes():
    """List all managed processes"""
    return jsonify({"processes": process_manager.list_processes()})


@app.route("/api/processes/<int:pid>", methods=["GET"])
@require_auth
def get_process_info(pid):
    """Get detailed process information"""
    info = process_manager.get_process_info(pid)
    if info:
        return jsonify(info)
    return jsonify({"error": "Process not found"}), 404


@app.route("/api/processes/<int:pid>/terminate", methods=["POST"])
@require_auth
def terminate_process(pid):
    """Terminate a process"""
    if process_manager.terminate_process(pid):
        return jsonify({"message": f"Process {pid} terminated"})
    return jsonify({"error": f"Failed to terminate process {pid}"}), 500


@app.route("/api/processes/dashboard", methods=["GET"])
@require_auth
def get_process_dashboard():
    """Get process dashboard with system metrics"""
    return jsonify(process_manager.get_dashboard())


@app.route("/api/processes/stats", methods=["GET"])
@require_auth
def get_process_stats():
    """Get process statistics"""
    return jsonify(process_manager.get_stats())


# ═════════════════════════════════════════════════════════════════════════════
# CACHE MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/cache/stats", methods=["GET"])
@require_auth
def get_cache_stats():
    """Get cache statistics"""
    stats = cache_manager.get_stats()
    stats["size_mb"] = round(cache_manager.get_size_mb(), 2)
    return jsonify(stats)


@app.route("/api/cache/clear", methods=["POST"])
@require_auth
def clear_cache():
    """Clear all cache"""
    cache_manager.clear()
    return jsonify({"message": "Cache cleared"})


# ═════════════════════════════════════════════════════════════════════════════
# HEALTH & TELEMETRY
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health_check():
    """Comprehensive health check with system metrics"""
    try:
        # Get tool availability
        availability = tool_registry.get_availability_stats()
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        process_count = len(psutil.pids())
        
        # Get active processes
        active_processes = process_manager.list_processes()
        
        # Cache stats
        cache_stats = cache_manager.get_stats()
        
        health_data = {
            "status": "healthy",
            "version": "7.0.0",
            "timestamp": datetime.now().isoformat(),
            "uptime": "check_availability",
            "auth": {
                "enabled": AUTH_ENABLED,
                "status": auth_manager.get_status()
            },
            "tools": {
                "total": availability["total"],
                "available": availability["available"],
                "availability_percent": availability["availability_percent"],
                "by_category": availability["by_category"]
            },
            "system": {
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(memory.percent, 2),
                "memory_mb": round(memory.used / (1024 * 1024), 2),
                "disk_percent": round(disk.percent, 2),
                "process_count": process_count
            },
            "cache": cache_stats,
            "processes": {
                "active": len(active_processes),
                "summary": process_manager.get_stats()
            }
        }
        
        return jsonify(health_data)
    
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/telemetry", methods=["GET"])
def telemetry():
    """Get telemetry data"""
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "cache": cache_manager.get_stats(),
        "processes": process_manager.get_stats(),
        "system": {
            "cpu_percent": round(psutil.cpu_percent(interval=0.1), 2),
            "memory_percent": round(psutil.virtual_memory().percent, 2)
        }
    })


# ═════════════════════════════════════════════════════════════════════════════
# GENERIC COMMAND EXECUTION (backward compatible)
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/command", methods=["POST"])
@require_auth
def generic_command():
    """Execute arbitrary command (backward compatible)"""
    try:
        data = request.json or {}
        command = data.get("command", "")
        use_cache = data.get("use_cache", False)
        
        if not command:
            return jsonify({"error": "Command is required"}), 400
        
        # Check cache
        if use_cache:
            cached = cache_manager.get(command)
            if cached:
                return jsonify({"result": cached, "cached": True})
        
        # Execute
        executor = CommandExecutor(command)
        result = executor.execute()
        
        # Cache if requested
        if result.get("success") and use_cache:
            cache_manager.set(command, result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Command error: {e}")
        return jsonify({"error": str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════════
# INTELLIGENT ANALYSIS ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/intelligence/analyze-target", methods=["POST"])
@require_auth
def analyze_target():
    """
    AI-powered target analysis and mission initiation
    """
    try:
        data = request.json or {}
        target = data.get("target", "")
        context = data.get("context", {})
        allow_install = True  # Always allow install to avoid skipping tools as requested
        scan_profile = str(context.get("scan_profile", "balanced")).lower()
        owasp_mode = bool(context.get("owasp_top10_mode", False))
        agent_name = "RedTeamer" if str(context.get("agent_profile", "bugbounty")).lower().startswith("red") else "BugBounty-1"
        
        if not target:
            return jsonify({"error": "target is required"}), 400
        
        # 1. Analyze target and get strategy
        analysis = decision_engine.analyze_target(target, context)
        tools = list(analysis.get("suggested_tools", []))
        
        # 2. Initialize Mission in Manager
        mission_id = mission_manager.start_mission(target, tools)
        
        # 3. Launch background mission thread
        def run_mission(target, analysis, mission_id):
            try:
                full_results = []
                execution_details = []
                normalized_target = normalize_target(target)
                target_url = normalized_target["url"]
                target_host = normalized_target["host"]
                wordlist_path = ensure_wordlist()
                
                for tool_name in tools:
                    mission_manager.update_status(mission_id, "RUNNING", current_tool=tool_name, log=f"Starting engine: {tool_name}")
                    
                    availability = ensure_tool_available(tool_name, allow_install=allow_install)
                    if not availability.get("available"):
                        logger.warning(f"Tool {tool_name} not found or unavailable.")
                        mission_manager.update_status(mission_id, "RUNNING", log=f"Tool '{tool_name}' unavailable. Phase skipped.")
                        full_results.append(f"--- TOOL: {tool_name} ---\n[ERROR] Tool not installed on host system.\n")
                        execution_details.append({
                            "tool": tool_name,
                            "command": "",
                            "success": False,
                            "timed_out": False,
                            "return_code": -1,
                            "stdout": "",
                            "stderr": "Tool unavailable or installation failed"
                        })
                        continue
                    if availability.get("installed"):
                        mission_manager.update_status(mission_id, "RUNNING", log=f"Installed missing tool '{tool_name}' via {availability.get('method')}.")

                    cmd = get_tool_command(tool_name, target_url, target_host, scan_profile=scan_profile)
                    if "{WORDLIST}" in cmd:
                        cmd = cmd.replace("{WORDLIST}", wordlist_path)
                    timeout = get_tool_timeout(tool_name, scan_profile=scan_profile)
                    executor = CommandExecutor(cmd, timeout=timeout)
                    result = executor.execute()
                    execution_details.append({
                        "tool": tool_name,
                        "command": cmd,
                        "success": bool(result.get("success")),
                        "timed_out": bool(result.get("timed_out")),
                        "return_code": result.get("return_code"),
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", "")
                    })
                    
                    if result.get("success") or result.get("partial_results"):
                        mission_manager.complete_tool(mission_id, tool_name)
                        output = result.get('stdout', '')
                        if not output: output = "[INFO] Tool executed but returned no output."
                        mission_manager.update_status(mission_id, "RUNNING", log=f"Engine {tool_name} completed. RAW OUTPUT:\n{output}")
                        full_results.append(f"--- TOOL: {tool_name} ---\n{output}\n")
                    else:
                        error_msg = result.get('stderr', 'Unknown error')
                        if result.get("timed_out"):
                            mission_manager.update_status(
                                mission_id,
                                "RUNNING",
                                log=f"Engine {tool_name} timed out after {timeout}s. Continuing with partial results."
                            )
                        else:
                            mission_manager.update_status(mission_id, "RUNNING", log=f"Engine {tool_name} failed: {error_msg[:50]}...")
                        full_results.append(f"--- TOOL: {tool_name} ---\n[FAILED] {error_msg}\n")
                    
                # 4. AI Analysis
                mission_manager.update_status(mission_id, "ANALYZING", log="AI analysis in progress...")
                consolidated_output = "\n".join(full_results)
                if owasp_mode:
                    mission_manager.update_status(mission_id, "ANALYZING", log="OWASP Top 10 analysis in progress...")
                    final_analysis = ai_backend.analyze_owasp_top10(consolidated_output, target=target)
                else:
                    final_analysis = ai_backend.analyze_vulnerability(consolidated_output)
                
                # 5. Save to history
                history_manager.save_scan(
                    target=target,
                    agent=agent_name + ("-OWASP" if owasp_mode else ""),
                    status="COMPLETED",
                    analysis=final_analysis.get("analysis", ""),
                    execution_details=execution_details
                )
                mission_manager.update_status(mission_id, "COMPLETED", log="Mission complete.")
                
            except Exception as e:
                logger.error(f"Mission {mission_id} failed: {e}")
                mission_manager.update_status(mission_id, "FAILED", log=f"Error: {str(e)}")

        thread = threading.Thread(target=run_mission, args=(target, analysis, mission_id))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "mission_id": mission_id,
            "message": "Mission initiated",
            "strategy": analysis.get("recommended_strategy"),
            "tools": tools,
            "agent_profile": analysis.get("agent_profile", "bugbounty"),
            "scan_profile": analysis.get("scan_profile", scan_profile),
            "owasp_top10_mode": analysis.get("owasp_top10_mode", owasp_mode)
        })
    
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/mission/<mission_id>/status", methods=["GET"])
@require_auth
def get_mission_status(mission_id):
    """Get real-time status of a specific mission"""
    return jsonify(mission_manager.get_status(mission_id))


@app.route("/api/intelligence/select-tools", methods=["POST"])
@require_auth
def select_tools():
    """
    Intelligent tool selection based on objectives
    """
    try:
        data = request.json or {}
        target = data.get("target", "")
        objectives = data.get("objectives", [])
        
        if not target or not objectives:
            return jsonify({"error": "target and objectives are required"}), 400
        
        selected_tools = decision_engine.select_tools(target, objectives)
        
        # Get tool info for each selected tool
        tool_details = []
        for selection in selected_tools:
            tool_name = selection["tool"]
            info = tool_registry.get_tool_info(tool_name)
            if info:
                info["selection_reason"] = selection["reason"]
                tool_details.append(info)
        
        return jsonify({
            "selected_tools": selected_tools,
            "tool_details": tool_details,
            "count": len(tool_details)
        })
    
    except Exception as e:
        logger.error(f"Tool selection error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
@require_auth
def optimize_parameters():
    """
    Optimize tool parameters based on target context
    """
    try:
        data = request.json or {}
        tool_name = data.get("tool_name", "")
        parameters = data.get("parameters", {})
        target_info = data.get("target_info", {})
        
        if not tool_name or not parameters:
            return jsonify({"error": "tool_name and parameters are required"}), 400
        
        optimized = decision_engine.optimize_parameters(tool_name, parameters, target_info)
        return jsonify({"optimized_parameters": optimized})
    
    except Exception as e:
        logger.error(f"Optimization error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
@require_auth
def get_scan_history():
    """Get scan history"""
    return jsonify({"history": history_manager.get_history()})


@app.route("/api/reports/generate/<scan_id>", methods=["POST"])
@require_auth
def generate_report(scan_id):
    """Manually generate a report for a specific scan"""
    history = history_manager.get_history()
    scan_data = next((s for s in history if s["id"] == scan_id), None)
    
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404
    
    filepath = reporter.generate_report(scan_data)
    if filepath:
        return jsonify({"message": "Report generated", "path": filepath})
    return jsonify({"error": "Failed to generate report"}), 500


@app.route("/api/settings", methods=["GET"])
@require_auth
def get_settings():
    """Get current server settings (filtered)"""
    return jsonify({
        "port": API_PORT,
        "auth_enabled": AUTH_ENABLED,
        "cache_size": CACHE_SIZE,
        "debug_mode": DEBUG_MODE,
        "model": os.environ.get("SKYFALL_MODEL", "openai/gpt-4o")
    })


@app.route("/api/intelligence/ai-analyze", methods=["POST"])
@require_auth
def ai_analyze():
    """
    Perform deep AI analysis of scan results
    """
    try:
        data = request.json or {}
        tool_output = data.get("output", "")
        
        if not tool_output:
            return jsonify({"error": "tool output is required"}), 400
        
        analysis = ai_backend.analyze_vulnerability(tool_output)
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"AI Analysis error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/ensure", methods=["POST"])
@require_auth
def ensure_tools():
    """
    Validate required tools on Kali and optionally install missing tools
    using APT / GitHub go-install when explicitly enabled.
    """
    try:
        data = request.json or {}
        tools = data.get("tools", [])
        allow_install = bool(data.get("allow_install", False))

        if not isinstance(tools, list) or not tools:
            return jsonify({"error": "tools list is required"}), 400

        results = [ensure_tool_available(t, allow_install=allow_install) for t in tools]
        ready = all(r.get("available") for r in results)
        return jsonify({
            "auto_install_enabled": AUTO_INSTALL_ENABLED,
            "allow_install": allow_install,
            "ready": ready,
            "results": results
        })
    except Exception as e:
        logger.error(f"Ensure tools error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/interactive/chat", methods=["POST"])
@require_auth
def interactive_chat():
    """
    Handle direct interaction from the Live Interactive UI
    """
    try:
        data = request.json or {}
        message = data.get("message", "")
        mission_id = data.get("mission_id")
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
            
        # 1. Use AI to interpret the message
        # If it looks like a command, we can run it
        # 1. Use AI to interpret the message intent
        intent_prompt = f"""
        Analyze the user's message: '{message}'
        Determine if the user wants:
        1. A FULL autonomous penetration test (multi-tool scan).
        2. To run a SINGLE specific tool/command.
        3. Just a general chat/question.
        
        If it's a FULL PT, return: 'FULL_PT: <target>'
        If it's a SINGLE command, return: 'EXECUTE: <command>'
        Otherwise, return a conversational response.
        """
        ai_response = ai_backend.query(intent_prompt, "You are a specialized Red Teamer and mission controller.")
        
        if ai_response.startswith("FULL_PT:"):
            target = ai_response.replace("FULL_PT:", "").strip()
            if target and ("." in target or "localhost" in target):
                return jsonify({
                    "response": f"Affirmative. Initializing Full Blackhat-style Penetration Test for: `{target}`. Engaging mission protocols.",
                    "action": "start_mission",
                    "target": target
                })

        if ai_response.startswith("EXECUTE:"):
            command = ai_response.replace("EXECUTE:", "").strip()
            tool_name = command.split()[0]
            
            # Execute the command
            executor = CommandExecutor(command, timeout=300)
            result = executor.execute()
            output = result.get("stdout") or result.get("stderr") or "No output from command."
            
            return jsonify({
                "response": f"Task Executed: `{command}`\n\nOUTPUT:\n{output}",
                "action": "execute",
                "command": command,
                "tool": tool_name,
                "output": output
            })
        
        return jsonify({
            "response": ai_response,
            "action": "none"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history/delete/<scan_id>", methods=["DELETE"])
@require_auth
def delete_history(scan_id):
    """Delete a scan from history"""
    if history_manager.delete_scan(scan_id):
        return jsonify({"success": True})
    return jsonify({"error": "Scan not found"}), 404


# ═════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Render the master control dashboard"""
    return render_template("dashboard.html")


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500


# ═════════════════════════════════════════════════════════════════════════════
# STARTUP & SHUTDOWN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Skyfall AI MCP Server v7.0 - Cybersecurity Automation Platform"
    )
    parser.add_argument("--port", type=int, default=API_PORT,
                        help=f"Server port (default: {API_PORT})")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--auth", action="store_true", help="Enable authentication")
    parser.add_argument("--no-auth", action="store_true", help="Disable authentication")
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Update settings from args
    if args.debug:
        os.environ["DEBUG_MODE"] = "1"
        app.debug = True
    if args.auth:
        os.environ["SKYFALL_AUTH_ENABLED"] = "1"
    if args.no_auth:
        os.environ["SKYFALL_AUTH_ENABLED"] = "0"
    
    print_banner()
    
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)
