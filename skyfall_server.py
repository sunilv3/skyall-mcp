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
import subprocess
import sys
import traceback
import threading
import psutil
from functools import wraps
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

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

# Initialize Flask app
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Initialize core managers
auth_manager = AuthenticationManager(enabled=AUTH_ENABLED)
tool_registry = ToolRegistry()
cache_manager = LRUCache(max_size=CACHE_SIZE, ttl_seconds=CACHE_TTL)
process_manager = ProcessManager()
decision_engine = IntelligentDecisionEngine(tool_registry)
ai_backend = AIBackend()
history_manager = HistoryManager()
notifier = Notifier()
reporter = Reporter()

# Define Banner
BANNER = f"""
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
    AI-powered target analysis
    Suggests optimal tools and testing strategies using IntelligentDecisionEngine
    """
    try:
        data = request.json or {}
        target = data.get("target", "")
        context = data.get("context", {})
        
        if not target:
            return jsonify({"error": "target is required"}), 400
        
        analysis = decision_engine.analyze_target(target, context)
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"error": str(e)}), 500


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
