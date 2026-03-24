#!/usr/bin/env python3

# MCP Kali Server - API Bridge for AI-assisted penetration testing
# Copyright (c) 2025 Skyfall (https://github.com/sunilv3)
# Inspired by https://github.com/whit3rabbit0/project_astro

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
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout

app = Flask(__name__)


class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.use_shell = isinstance(command, str)
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line

    def _read_stderr(self):
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing command: {self.command}")
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout}s. Terminating.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("Force killing process.")
                    self.process.kill()
                self.return_code = -1

            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command) -> Dict[str, Any]:
    executor = CommandExecutor(command)
    return executor.execute()


# ─────────────────────────────────────────────────────────────────────────────
# GENERIC COMMAND
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        if not command:
            return jsonify({"error": "Command parameter is required"}), 400
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["nmap"] + shlex.split(scan_type)
        if ports:
            command += ["-p", ports]
        if additional_args:
            command += shlex.split(additional_args)
        command.append(target)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            return jsonify({"error": f"Invalid mode: {mode}"}), 400
        command = ["gobuster", mode, "-u", url, "-w", wordlist]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["dirb", url, wordlist]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["nikto", "-h", target]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "--batch")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["sqlmap", "-u", url]
        if data:
            command += ["--data", data]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute a Metasploit module."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        if not module:
            return jsonify({"error": "Module parameter is required"}), 400
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"error": "Invalid module path"}), 400
        resource_content = f"use {module}\n"
        for key, value in options.items():
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)
        try:
            os.remove(resource_file)
        except Exception:
            pass
        return jsonify(result)
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        if not target or not service:
            return jsonify({"error": "Target and service are required"}), 400
        if not (username or username_file) or not (password or password_file):
            return jsonify({"error": "Username and password (or files) are required"}), 400
        command = ["hydra", "-t", "4"]
        if username:
            command += ["-l", username]
        elif username_file:
            command += ["-L", username_file]
        if password:
            command += ["-p", password]
        elif password_file:
            command += ["-P", password_file]
        command += [target, service]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute John the Ripper."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        if not hash_file:
            return jsonify({"error": "Hash file parameter is required"}), 400
        command = ["john"]
        if format_type:
            command.append(f"--format={format_type}")
        if wordlist:
            command.append(f"--wordlist={wordlist}")
        if additional_args:
            command += shlex.split(additional_args)
        command.append(hash_file)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute WPScan."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["wpscan", "--url", url]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["enum4linux"] + shlex.split(additional_args) + [target]
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# NEW: WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """
    Detect Web Application Firewalls using wafw00f.
    Install: pip install wafw00f
    """
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["wafw00f", url]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# NEW: XSS SCANNING
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/dalfox", methods=["POST"])
def dalfox():
    """
    XSS scanning using dalfox.
    Install: go install github.com/hahwul/dalfox/v2@latest
    Modes: url, pipe, file, server
    """
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "url")
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        if mode not in ["url", "pipe", "file", "server"]:
            return jsonify({"error": f"Invalid dalfox mode: {mode}"}), 400
        command = ["dalfox", mode, url]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/xsstrike", methods=["POST"])
def xsstrike():
    """
    Advanced XSS detection using XSStrike.
    Install: git clone https://github.com/s0md3v/XSStrike
    """
    try:
        params = request.json
        url = params.get("url", "")
        crawl = params.get("crawl", False)
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["python3", "/opt/XSStrike/xsstrike.py", "-u", url]
        if crawl:
            command.append("--crawl")
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# NEW: ADVANCED RECON
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """
    Passive subdomain enumeration using subfinder.
    Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    """
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        command = ["subfinder", "-d", domain, "-silent"]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """
    In-depth attack surface mapping using amass.
    Install: sudo apt install amass
    """
    try:
        params = request.json
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")  # enum, intel, track, viz
        additional_args = params.get("additional_args", "-passive")
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        command = ["amass", mode, "-d", domain]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """
    Fast HTTP probing using httpx.
    Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    Accepts a list of hosts or a single URL.
    """
    try:
        params = request.json
        hosts = params.get("hosts", [])       # list of hosts/URLs
        url = params.get("url", "")            # single target
        additional_args = params.get("additional_args", "-title -status-code -tech-detect")
        if not hosts and not url:
            return jsonify({"error": "Either 'hosts' list or 'url' is required"}), 400
        if hosts:
            # Pipe through echo
            host_input = "\n".join(hosts)
            command = f"echo '{host_input}' | httpx {additional_args}"
        else:
            command = f"httpx -u {url} {additional_args}"
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """
    Template-based vulnerability scanning using nuclei.
    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    """
    try:
        params = request.json
        target = params.get("target", "")
        templates = params.get("templates", "")        # e.g. "cves/" or "exposures/"
        severity = params.get("severity", "")          # critical,high,medium,low,info
        additional_args = params.get("additional_args", "")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["nuclei", "-u", target]
        if templates:
            command += ["-t", templates]
        if severity:
            command += ["-severity", severity]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """
    Fast web fuzzer using ffuf.
    Install: sudo apt install ffuf
    Use FUZZ as the placeholder in the URL, headers, or data.
    """
    try:
        params = request.json
        url = params.get("url", "")            # Must contain FUZZ keyword
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        filter_code = params.get("filter_code", "404")
        additional_args = params.get("additional_args", "")
        if not url or "FUZZ" not in url:
            return jsonify({"error": "URL with FUZZ placeholder is required"}), 400
        command = ["ffuf", "-u", url, "-w", wordlist]
        if filter_code:
            command += ["-fc", filter_code]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """
    Web technology fingerprinting using whatweb.
    Install: sudo apt install whatweb
    """
    try:
        params = request.json
        url = params.get("url", "")
        aggression = params.get("aggression", 1)   # 1 (stealthy) to 4 (aggressive)
        additional_args = params.get("additional_args", "")
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        command = ["whatweb", f"--aggression={aggression}", url]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/theHarvester", methods=["POST"])
def theharvester():
    """
    OSINT / email & subdomain harvesting using theHarvester.
    Install: sudo apt install theharvester
    """
    try:
        params = request.json
        domain = params.get("domain", "")
        sources = params.get("sources", "all")   # e.g. google,bing,shodan
        limit = params.get("limit", 200)
        additional_args = params.get("additional_args", "")
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        command = ["theHarvester", "-d", domain, "-b", sources, "-l", str(limit)]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/dnsx", methods=["POST"])
def dnsx():
    """
    Fast DNS resolution & enumeration using dnsx.
    Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    """
    try:
        params = request.json
        domain = params.get("domain", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "-a -aaaa -cname -mx -ns -txt")
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        if wordlist:
            command = f"dnsx -d {domain} -w {wordlist} {additional_args}"
        else:
            command = f"dnsx -d {domain} {additional_args}"
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/sslscan", methods=["POST"])
def sslscan():
    """
    SSL/TLS configuration scanner using sslscan.
    Install: sudo apt install sslscan
    """
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["sslscan", target]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/shodan", methods=["POST"])
def shodan():
    """
    Shodan CLI lookup for a target IP/domain.
    Install: pip install shodan && shodan init YOUR_API_KEY
    """
    try:
        params = request.json
        target = params.get("target", "")
        subcommand = params.get("subcommand", "host")  # host, search, count, etc.
        additional_args = params.get("additional_args", "")
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        command = ["shodan", subcommand, target]
        if additional_args:
            command += shlex.split(additional_args)
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# ADVANCED SQLMap — red-team grade, low false positives
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/sqlmap_advanced", methods=["POST"])
def sqlmap_advanced():
    """
    Advanced SQLmap with tamper scripts, technique control, and verification.
    Uses --confirm + --not-string tricks to kill false positives.
    Install: already in Kali (sqlmap)
    """
    try:
        params = request.json
        url          = params.get("url", "")
        data         = params.get("data", "")           # POST body
        cookie       = params.get("cookie", "")
        headers      = params.get("headers", "")        # extra headers
        level        = params.get("level", 3)           # 1-5
        risk         = params.get("risk", 2)            # 1-3
        technique    = params.get("technique", "BEUSTQ")# B=boolean, E=error, U=union, S=stacked, T=time, Q=inline
        tamper       = params.get("tamper", "")         # e.g. "space2comment,between"
        dbms         = params.get("dbms", "")           # target DBMS hint
        dump         = params.get("dump", False)
        dbs          = params.get("dbs", False)
        tables       = params.get("tables", False)
        os_shell     = params.get("os_shell", False)
        threads      = params.get("threads", 5)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = [
            "sqlmap", "-u", url,
            "--batch",                        # non-interactive
            "--smart",                        # only test promising params
            "--level", str(level),
            "--risk",  str(risk),
            "--technique", technique,
            "--threads", str(threads),
            "--output-dir", "/tmp/sqlmap_out",
            "--time-sec", "8",                # avoid flaky time-based FPs
            "--retries", "3",
        ]

        if data:
            command += ["--data", data]
        if cookie:
            command += ["--cookie", cookie]
        if headers:
            for h in headers.split("\n"):
                if h.strip():
                    command += ["--headers", h.strip()]
        if tamper:
            command += ["--tamper", tamper]
        if dbms:
            command += ["--dbms", dbms]
        if dbs:
            command.append("--dbs")
        if tables:
            command.append("--tables")
        if dump:
            command.append("--dump")
        if os_shell:
            command.append("--os-shell")
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """
    Crawl archived URLs to find parameters using ParamSpider.
    Install: pip install paramspider
    """
    try:
        params  = request.json
        domain  = params.get("domain", "")
        level   = params.get("level", "high")   # high/medium/low
        exclude = params.get("exclude", "png,jpg,gif,css,js,woff")
        output  = params.get("output", "/tmp/paramspider_out.txt")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = [
            "paramspider", "-d", domain,
            "--level", level,
            "--exclude", exclude,
            "-o", output,
        ]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """
    Hidden HTTP parameter discovery using Arjun.
    Install: pip install arjun
    Tests GET, POST (form/json/xml) parameters with smart heuristics.
    """
    try:
        params  = request.json
        url     = params.get("url", "")
        method  = params.get("method", "GET")       # GET, POST, JSON, XML
        wordlist= params.get("wordlist", "")         # default: built-in 25k list
        threads = params.get("threads", 5)
        stable  = params.get("stable", True)         # slower but fewer FPs
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = [
            "arjun", "-u", url,
            "-m", method.upper(),
            "-t", str(threads),
            "--rate-limit", "5",            # polite; avoids rate-limit FPs
        ]
        if wordlist:
            command += ["-w", wordlist]
        if stable:
            command.append("--stable")
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/katana", methods=["POST"])
def katana():
    """
    Fast, intelligent web crawler using katana (ProjectDiscovery).
    Extracts endpoints, JS-sourced URLs, and forms.
    Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
    """
    try:
        params  = request.json
        url     = params.get("url", "")
        depth   = params.get("depth", 3)
        js_crawl= params.get("js_crawl", True)
        headless= params.get("headless", False)   # True for JS-heavy SPAs
        output  = params.get("output", "/tmp/katana_out.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = [
            "katana", "-u", url,
            "-depth", str(depth),
            "-o", output,
            "-silent",
            "-no-color",
        ]
        if js_crawl:
            command.append("-js-crawl")
        if headless:
            command.append("-headless")
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# INJECTION SCANNERS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/commix", methods=["POST"])
def commix():
    """
    Automated OS command injection using commix.
    Install: sudo apt install commix
    """
    try:
        params  = request.json
        url     = params.get("url", "")
        data    = params.get("data", "")
        cookie  = params.get("cookie", "")
        level   = params.get("level", 2)         # 1-3
        technique = params.get("technique", "")  # classic/dynamic/time
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = [
            "commix", "--url", url,
            "--batch",
            "--level", str(level),
        ]
        if data:
            command += ["--data", data]
        if cookie:
            command += ["--cookie", cookie]
        if technique:
            command += ["--technique", technique]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/ghauri", methods=["POST"])
def ghauri():
    """
    Advanced SQL injection tool (fewer false positives than sqlmap for some targets).
    Install: pip install ghauri
    """
    try:
        params   = request.json
        url      = params.get("url", "")
        data     = params.get("data", "")
        cookie   = params.get("cookie", "")
        level    = params.get("level", 3)
        technique= params.get("technique", "")   # B/E/T/S/U
        dbs      = params.get("dbs", False)
        dump     = params.get("dump", False)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["ghauri", "-u", url, "--batch", "--level", str(level), "--confirm"]
        if data:
            command += ["--data", data]
        if cookie:
            command += ["--cookie", cookie]
        if technique:
            command += ["--technique", technique]
        if dbs:
            command.append("--dbs")
        if dump:
            command.append("--dump")
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# MISCONFIGURATION / WEB SCANNERS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/tools/corsy", methods=["POST"])
def corsy():
    """
    CORS misconfiguration scanner using corsy.
    Install: pip install corsy
    """
    try:
        params  = request.json
        url     = params.get("url", "")
        headers = params.get("headers", "")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["python3", "/opt/Corsy/corsy.py", "-u", url, "-t", str(threads)]
        if headers:
            command += ["-H", headers]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/crlfuzz", methods=["POST"])
def crlfuzz():
    """
    CRLF injection scanner using crlfuzz.
    Install: go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
    """
    try:
        params  = request.json
        url     = params.get("url", "")
        method  = params.get("method", "GET")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["crlfuzz", "-u", url, "-X", method.upper(), "-s"]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/smuggler", methods=["POST"])
def smuggler():
    """
    HTTP Request Smuggling detection using smuggler.py.
    Install: git clone https://github.com/defparam/smuggler /opt/smuggler
    """
    try:
        params   = request.json
        url      = params.get("url", "")
        method   = params.get("method", "POST")
        timeout  = params.get("timeout", 5)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = [
            "python3", "/opt/smuggler/smuggler.py",
            "-u", url,
            "-m", method.upper(),
            "--timeout", str(timeout),
            "-q",   # quiet — only confirmed findings
        ]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/gitdumper", methods=["POST"])
def gitdumper():
    """
    Dump exposed .git directories using git-dumper.
    Install: pip install git-dumper
    """
    try:
        params  = request.json
        url     = params.get("url", "")            # e.g. https://target.com/.git
        output  = params.get("output", "/tmp/git_dump")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["git-dumper", url, output]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/nmap_advanced", methods=["POST"])
def nmap_advanced():
    """
    Advanced Nmap with NSE script presets for red team recon.
    Presets: vuln, auth, brute, discovery, safe, intrusive
    """
    try:
        params   = request.json
        target   = params.get("target", "")
        preset   = params.get("preset", "vuln")     # vuln | auth | brute | discovery | safe | intrusive
        ports    = params.get("ports", "")           # e.g. "80,443,8080-8090"
        os_detect= params.get("os_detect", True)
        traceroute = params.get("traceroute", False)
        output   = params.get("output", "/tmp/nmap_adv.xml")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        valid_presets = ["vuln", "auth", "brute", "discovery", "safe", "intrusive"]
        if preset not in valid_presets:
            return jsonify({"error": f"Preset must be one of: {valid_presets}"}), 400

        command = [
            "nmap",
            "-sCV",
            f"--script={preset}",
            "-T4", "-Pn",
            "--open",                       # only show open ports — reduces noise
            "-oX", output,
        ]
        if ports:
            command += ["-p", ports]
        else:
            command.append("--top-ports=1000")
        if os_detect:
            command.append("-O")
        if traceroute:
            command.append("--traceroute")
        if additional_args:
            command += shlex.split(additional_args)
        command.append(target)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/linkfinder", methods=["POST"])
def linkfinder():
    """
    Extract endpoints from JavaScript files using LinkFinder.
    Install: git clone https://github.com/GerbenJavado/LinkFinder /opt/linkfinder
             pip install -r /opt/linkfinder/requirements.txt
    """
    try:
        params   = request.json
        url      = params.get("url", "")          # JS file URL or page URL
        output   = params.get("output", "cli")    # cli or burp
        crawl    = params.get("crawl", False)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["python3", "/opt/linkfinder/linkfinder.py", "-i", url, "-o", output]
        if crawl:
            command.append("-c")
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/gau", methods=["POST"])
def gau():
    """
    Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl using gau.
    Install: go install github.com/lc/gau/v2/cmd/gau@latest
    Great source of params for SQLi/XSS fuzzing.
    """
    try:
        params   = request.json
        domain   = params.get("domain", "")
        blacklist= params.get("blacklist", "png,jpg,gif,css,woff,svg")
        threads  = params.get("threads", 10)
        providers= params.get("providers", "wayback,otx,commoncrawl")
        output   = params.get("output", "/tmp/gau_out.txt")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = [
            "gau", domain,
            "--threads", str(threads),
            "--providers", providers,
            "--blacklist", blacklist,
            "--o", output,
        ]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint — reports status of all tools."""
    tools = [
        # Core tools
        "nmap", "gobuster", "dirb", "nikto", "sqlmap",
        "hydra", "john", "wpscan", "enum4linux",
        # Recon & fingerprinting
        "wafw00f", "subfinder", "amass", "httpx",
        "nuclei", "ffuf", "whatweb", "theHarvester",
        "dnsx", "sslscan", "shodan",
        # XSS
        "dalfox",
        # Parameter discovery
        "arjun", "katana", "gau",
        # Injection
        "commix", "ghauri",
        # Misc
        "crlfuzz",
    ]
    tools_status = {}
    for tool in tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception:
            tools_status[tool] = False

    essential = ["nmap", "gobuster", "dirb", "nikto"]
    all_essential = all(tools_status.get(t, False) for t in essential)

    return jsonify({
        "status": "healthy",
        "message": "MCP Kali Server (by Skyfall) is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential
    })


# ─────────────────────────────────────────────────────────────────────────────
# STUB ENDPOINTS (future use)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    pass


@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Run the MCP Kali API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT,
                        help=f"Port (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1",
                        help="IP to bind (default: 127.0.0.1)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    if args.port != API_PORT:
        API_PORT = args.port
    logger.info(f"Starting MCP Kali Server (by Skyfall) on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
