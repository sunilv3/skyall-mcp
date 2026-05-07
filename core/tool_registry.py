#!/usr/bin/env python3
"""
Dynamic Tool Registry for Skyfall AI MCP v7.0
Manages 150+ security tools without hitting MCP client registration limits
"""

import logging
import shlex
import subprocess
import os
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ToolParameter:
    """Represents a tool parameter"""
    name: str
    type: str  # string, integer, boolean, array, object
    required: bool = False
    description: str = ""
    default: Any = None
    choices: List[str] = None
    flag: Optional[str] = None  # e.g., "-u", "--target", "-p"


@dataclass
class Tool:
    """Represents a security tool"""
    name: str
    category: str
    description: str
    command: str
    parameters: List[ToolParameter]
    examples: List[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "command": self.command,
            "parameters": [asdict(p) for p in self.parameters],
            "examples": self.examples or []
        }


class ToolRegistry:
    """Registry for managing security tools"""
    
    CATEGORIES = {
        "network": "Network Reconnaissance & Scanning",
        "web": "Web Application Security",
        "auth": "Authentication & Password Testing",
        "binary": "Binary Analysis & Reverse Engineering",
        "cloud": "Cloud & Container Security",
        "ctf": "CTF & Forensics Tools",
        "osint": "OSINT & Intelligence",
        "misc": "Miscellaneous Tools"
    }
    
    def __init__(self):
        """Initialize tool registry"""
        self.tools: Dict[str, Tool] = {}
        self._register_tools()
        logger.info(f"Initialized tool registry with {len(self.tools)} tools")
    
    def _register_tools(self):
        """Register all available security tools with full parameter mapping"""
        
        # ── NETWORK RECONNAISSANCE ───────────────────────────────────────────
        self.register_tool(Tool(
            name="nmap",
            category="network",
            description="Advanced port scanning with custom NSE scripts",
            command="nmap",
            parameters=[
                ToolParameter("target", "string", required=True, flag=""),
                ToolParameter("scan_type", "string", default="-sCV", flag=""),
                ToolParameter("ports", "string", flag="-p"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="nmap_advanced",
            category="network",
            description="Advanced Nmap with NSE script presets",
            command="nmap",
            parameters=[
                ToolParameter("target", "string", required=True, flag=""),
                ToolParameter("preset", "string", default="vuln", flag="--script"),
                ToolParameter("ports", "string", flag="-p"),
                ToolParameter("os_detect", "boolean", default=True, flag="-O"),
                ToolParameter("traceroute", "boolean", default=False, flag="--traceroute"),
                ToolParameter("output", "string", flag="-oX"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="subfinder",
            category="network",
            description="Fast passive subdomain discovery",
            command="subfinder",
            parameters=[
                ToolParameter("domain", "string", required=True, flag="-d"),
                ToolParameter("silent", "boolean", default=True, flag="-silent"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="amass",
            category="network",
            description="In-depth attack surface mapping",
            command="amass",
            parameters=[
                ToolParameter("mode", "string", default="enum", flag=""),
                ToolParameter("domain", "string", required=True, flag="-d"),
                ToolParameter("additional_args", "string", flag="-passive")
            ]
        ))

        # ── WEB APPLICATION SECURITY ─────────────────────────────────────────
        self.register_tool(Tool(
            name="nuclei",
            category="web",
            description="Template-based vulnerability scanner",
            command="nuclei",
            parameters=[
                ToolParameter("target", "string", required=True, flag="-u"),
                ToolParameter("templates", "string", flag="-t"),
                ToolParameter("severity", "string", flag="-severity"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="sqlmap",
            category="web",
            description="Automatic SQL injection testing",
            command="sqlmap",
            parameters=[
                ToolParameter("url", "string", required=True, flag="-u"),
                ToolParameter("data", "string", flag="--data"),
                ToolParameter("level", "integer", default=3, flag="--level"),
                ToolParameter("risk", "integer", default=2, flag="--risk"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="sqlmap_advanced",
            category="web",
            description="Red-team grade SQLmap with full feature control",
            command="sqlmap",
            parameters=[
                ToolParameter("url", "string", required=True, flag="-u"),
                ToolParameter("data", "string", flag="--data"),
                ToolParameter("cookie", "string", flag="--cookie"),
                ToolParameter("level", "integer", default=3, flag="--level"),
                ToolParameter("risk", "integer", default=2, flag="--risk"),
                ToolParameter("technique", "string", default="BEUSTQ", flag="--technique"),
                ToolParameter("tamper", "string", flag="--tamper"),
                ToolParameter("dbms", "string", flag="--dbms"),
                ToolParameter("dump", "boolean", flag="--dump"),
                ToolParameter("dbs", "boolean", flag="--dbs"),
                ToolParameter("os_shell", "boolean", flag="--os-shell"),
                ToolParameter("threads", "integer", default=5, flag="--threads"),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="dalfox",
            category="web",
            description="Fast XSS scanning and parameter analysis",
            command="dalfox",
            parameters=[
                ToolParameter("mode", "string", default="url", flag=""),
                ToolParameter("url", "string", required=True, flag=""),
                ToolParameter("additional_args", "string", flag="")
            ]
        ))

        self.register_tool(Tool(
            name="wafw00f",
            category="web",
            description="Web Application Firewall fingerprinting",
            command="wafw00f",
            parameters=[
                ToolParameter("url", "string", required=True, flag=""),
                ToolParameter("additional_args", "string", flag="-a")
            ]
        ))

        # ── PARAMETER & ENDPOINT DISCOVERY ───────────────────────────────────
        self.register_tool(Tool(
            name="katana",
            category="web",
            description="Next-generation web crawling and spidering",
            command="katana",
            parameters=[
                ToolParameter("url", "string", required=True, flag="-u"),
                ToolParameter("depth", "integer", default=3, flag="-d"),
                ToolParameter("js_crawl", "boolean", default=True, flag="-jc"),
                ToolParameter("headless", "boolean", default=False, flag="-hl"),
                ToolParameter("output", "string", flag="-o")
            ]
        ))

        self.register_tool(Tool(
            name="arjun",
            category="web",
            description="HTTP parameter discovery suite",
            command="arjun",
            parameters=[
                ToolParameter("url", "string", required=True, flag="-u"),
                ToolParameter("method", "string", default="GET", flag="-m"),
                ToolParameter("threads", "integer", default=5, flag="-t")
            ]
        ))

        # ── CUSTOM INTEGRATED TOOLS ──────────────────────────────────────────
        import sys
        python_exe = sys.executable
        
        self.register_tool(Tool(
            name="subdomain_validator",
            category="network",
            description="Skyfall Custom Subdomain Validator (DNS/SSL/HTTP)",
            command=f"{python_exe} tools/subdomainchecker.py",
            parameters=[
                ToolParameter("domains", "string", required=True, flag="-d"),
                ToolParameter("threads", "integer", default=10, flag="-t"),
                ToolParameter("output", "string", flag="-o")
            ]
        ))

        self.register_tool(Tool(
            name="status_checker",
            category="web",
            description="Skyfall Custom Domain Status Checker (Bulk)",
            command=f"{python_exe} tools/statueschecker.py",
            parameters=[
                ToolParameter("domains", "string", required=True, flag="--domains"),
                ToolParameter("output", "string", flag="--output")
            ]
        ))

        # ── BULK REGISTRATION FOR ADDITIONAL TOOLS ──────────────────────────
        # Register the rest of the tools from skyfall_mcp.py with basic mapping
        additional_tools = [
            ("gobuster", "web", "Directory, file, and DNS enumeration"),
            ("nikto", "web", "Web server vulnerability scanner"),
            ("hydra", "auth", "Network login cracker"),
            ("john", "auth", "Password hash cracking"),
            ("wpscan", "web", "WordPress security scanner"),
            ("enum4linux", "network", "Windows/Samba enumeration"),
            ("xsstrike", "web", "Advanced XSS detection"),
            ("httpx", "web", "HTTP probing and tech detection"),
            ("ffuf", "web", "Fast web fuzzer"),
            ("whatweb", "web", "Web technology identification"),
            ("theHarvester", "osint", "OSINT gathering"),
            ("dnsx", "network", "DNS resolution and enumeration"),
            ("sslscan", "web", "SSL/TLS configuration scanner"),
            ("shodan", "osint", "Shodan CLI lookup"),
            ("paramspider", "web", "Injectable parameter mining"),
            ("gau", "web", "Historical URL fetching"),
            ("commix", "web", "OS command injection testing"),
            ("ghauri", "web", "Advanced SQL injection"),
            ("corsy", "web", "CORS misconfig scanner"),
            ("crlfuzz", "web", "CRLF injection scanner"),
            ("smuggler", "web", "HTTP Request Smuggling detection"),
            ("gitdumper", "web", "Exposed .git directory dumper"),
            ("linkfinder", "web", "JS endpoint extractor"),
            ("rustscan", "network", "Ultra-fast port scanner"),
            ("masscan", "network", "High-speed port scanning"),
            ("feroxbuster", "web", "Recursive content discovery")
        ]

        for name, cat, desc in additional_tools:
            if name not in self.tools:
                # Default to 'url' or 'target' based on category
                main_param = "url" if cat == "web" else "target"
                self.register_tool(Tool(
                    name=name, 
                    category=cat, 
                    description=desc, 
                    command=name, 
                    parameters=[ToolParameter(main_param, "string", required=True, flag="")]
                ))

        logger.info(f"Registered {len(self.tools)} tools with enhanced parameter mapping")

    def register_tool(self, tool: Tool):
        """Register a tool"""
        self.tools[tool.name] = tool
    
    def get_tool(self, tool_name: str) -> Optional[Tool]:
        """Get tool by name"""
        return self.tools.get(tool_name)
    
    def list_tools(self, category: Optional[str] = None) -> List[Dict]:
        """List all tools, optionally filtered by category"""
        result = []
        for tool in self.tools.values():
            if category is None or tool.category == category:
                result.append(tool.to_dict())
        return result
    
    def get_categories(self) -> Dict[str, List[Dict]]:
        """Get tools organized by category"""
        categories = {}
        for category_key, category_name in self.CATEGORIES.items():
            categories[category_key] = self.list_tools(category_key)
        return categories
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get detailed information about a tool"""
        tool = self.get_tool(tool_name)
        if tool:
            return tool.to_dict()
        return None
    
    def is_available(self, tool_name: str) -> bool:
        """Check if tool is available on system"""
        try:
            # Use 'where' on Windows, 'which' on Unix
            cmd = "where" if os.name == "nt" else "which"
            result = subprocess.run(
                [cmd, tool_name],
                capture_output=True,
                timeout=5,
                shell=(os.name == "nt")
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_availability_stats(self) -> Dict[str, Any]:
        """Get statistics on tool availability"""
        available = 0
        unavailable = 0
        by_category = {}
        
        for tool in self.tools.values():
            category = tool.category
            if category not in by_category:
                by_category[category] = {"available": 0, "unavailable": 0}
            
            if self.is_available(tool.name):
                available += 1
                by_category[category]["available"] += 1
            else:
                unavailable += 1
                by_category[category]["unavailable"] += 1
        
        return {
            "total": len(self.tools),
            "available": available,
            "unavailable": unavailable,
            "availability_percent": round((available / len(self.tools) * 100) if self.tools else 0, 2),
            "by_category": by_category
        }
