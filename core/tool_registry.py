#!/usr/bin/env python3
"""
Dynamic Tool Registry for Skyfall AI MCP v7.0
Manages 150+ security tools without hitting MCP client registration limits
"""

import logging
import shlex
import subprocess
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
        """Register all available security tools"""
        
        # Network Reconnaissance & Scanning
        self.register_tool(Tool(
            name="nmap",
            category="network",
            description="Advanced port scanning with custom NSE scripts",
            command="nmap",
            parameters=[
                ToolParameter("target", "string", required=True, description="Target host or IP"),
                ToolParameter("scan_type", "string", description="Scan type (e.g., -sCV)", default="-sCV"),
                ToolParameter("ports", "string", description="Ports to scan"),
                ToolParameter("additional_args", "string", description="Additional nmap arguments")
            ],
            examples=["nmap -sCV -T4 example.com", "nmap -p 80,443 example.com"]
        ))
        
        self.register_tool(Tool(
            name="rustscan",
            category="network",
            description="Ultra-fast port scanner with intelligent rate limiting",
            command="rustscan",
            parameters=[
                ToolParameter("target", "string", required=True, description="Target host or IP"),
                ToolParameter("ports", "string", description="Port range"),
                ToolParameter("additional_args", "string", description="Additional arguments")
            ]
        ))
        
        self.register_tool(Tool(
            name="masscan",
            category="network",
            description="High-speed Internet-scale port scanning",
            command="masscan",
            parameters=[
                ToolParameter("target", "string", required=True, description="Target CIDR range"),
                ToolParameter("ports", "string", description="Ports to scan", default="0-65535"),
                ToolParameter("rate", "integer", description="Packet rate", default=100000)
            ]
        ))
        
        self.register_tool(Tool(
            name="amass",
            category="network",
            description="Advanced subdomain enumeration and OSINT",
            command="amass",
            parameters=[
                ToolParameter("domain", "string", required=True, description="Target domain"),
                ToolParameter("mode", "string", description="Mode (enum/intel/track)", default="enum"),
                ToolParameter("passive", "boolean", description="Use passive sources", default=True)
            ]
        ))
        
        self.register_tool(Tool(
            name="subfinder",
            category="network",
            description="Fast passive subdomain discovery",
            command="subfinder",
            parameters=[
                ToolParameter("domain", "string", required=True, description="Target domain"),
                ToolParameter("silent", "boolean", description="Silent output", default=True)
            ]
        ))
        
        # Web Application Security
        self.register_tool(Tool(
            name="gobuster",
            category="web",
            description="Directory, file, and DNS enumeration",
            command="gobuster",
            parameters=[
                ToolParameter("url", "string", required=True, description="Target URL"),
                ToolParameter("mode", "string", description="Mode (dir/dns/fuzz)", default="dir"),
                ToolParameter("wordlist", "string", description="Wordlist path"),
                ToolParameter("additional_args", "string", description="Additional arguments")
            ]
        ))
        
        self.register_tool(Tool(
            name="nuclei",
            category="web",
            description="Template-based vulnerability scanner with 4000+ templates",
            command="nuclei",
            parameters=[
                ToolParameter("target", "string", required=True, description="Target URL"),
                ToolParameter("templates", "string", description="Template directory"),
                ToolParameter("severity", "string", description="Severity level"),
                ToolParameter("additional_args", "string", description="Additional arguments")
            ]
        ))
        
        self.register_tool(Tool(
            name="sqlmap",
            category="web",
            description="Automatic SQL injection testing with tamper scripts",
            command="sqlmap",
            parameters=[
                ToolParameter("url", "string", required=True, description="Target URL"),
                ToolParameter("data", "string", description="POST data"),
                ToolParameter("level", "integer", description="Test level (1-5)", default=3),
                ToolParameter("technique", "string", description="Technique (B/E/U/S/T/Q)")
            ]
        ))
        
        self.register_tool(Tool(
            name="ffuf",
            category="web",
            description="Fast web fuzzer with advanced filtering",
            command="ffuf",
            parameters=[
                ToolParameter("url", "string", required=True, description="URL with FUZZ placeholder"),
                ToolParameter("wordlist", "string", description="Wordlist path"),
                ToolParameter("filter_code", "string", description="Filter response codes")
            ]
        ))
        
        self.register_tool(Tool(
            name="feroxbuster",
            category="web",
            description="Recursive content discovery with intelligent filtering",
            command="feroxbuster",
            parameters=[
                ToolParameter("url", "string", required=True, description="Target URL"),
                ToolParameter("wordlist", "string", description="Wordlist path"),
                ToolParameter("additional_args", "string", description="Additional arguments")
            ]
        ))
        
        # Authentication & Password
        self.register_tool(Tool(
            name="hydra",
            category="auth",
            description="Network login cracker for 50+ protocols",
            command="hydra",
            parameters=[
                ToolParameter("target", "string", required=True, description="Target host"),
                ToolParameter("service", "string", required=True, description="Service (ssh/ftp/http)"),
                ToolParameter("username", "string", description="Username"),
                ToolParameter("password", "string", description="Password to try")
            ]
        ))
        
        self.register_tool(Tool(
            name="john",
            category="auth",
            description="Advanced password hash cracking",
            command="john",
            parameters=[
                ToolParameter("hash_file", "string", required=True, description="Hash file path"),
                ToolParameter("wordlist", "string", description="Wordlist path"),
                ToolParameter("format", "string", description="Hash format")
            ]
        ))
        
        self.register_tool(Tool(
            name="hashcat",
            category="auth",
            description="GPU-accelerated password recovery",
            command="hashcat",
            parameters=[
                ToolParameter("hash_file", "string", required=True, description="Hash file"),
                ToolParameter("attack_mode", "integer", description="Attack mode (0-9)"),
                ToolParameter("wordlist", "string", description="Wordlist path")
            ]
        ))
        
        # Binary Analysis & Reverse Engineering
        self.register_tool(Tool(
            name="ghidra",
            category="binary",
            description="NSA software reverse engineering suite",
            command="ghidra",
            parameters=[
                ToolParameter("binary", "string", required=True, description="Binary file path"),
                ToolParameter("script", "string", description="Ghidra script path")
            ]
        ))
        
        self.register_tool(Tool(
            name="radare2",
            category="binary",
            description="Advanced reverse engineering framework",
            command="r2",
            parameters=[
                ToolParameter("binary", "string", required=True, description="Binary file path"),
                ToolParameter("command", "string", description="Radare2 command")
            ]
        ))
        
        self.register_tool(Tool(
            name="gdb",
            category="binary",
            description="GNU Debugger with exploit development support",
            command="gdb",
            parameters=[
                ToolParameter("binary", "string", required=True, description="Binary file path"),
                ToolParameter("script", "string", description="GDB script path")
            ]
        ))
        
        self.register_tool(Tool(
            name="binwalk",
            category="binary",
            description="Firmware analysis and binary extraction",
            command="binwalk",
            parameters=[
                ToolParameter("file", "string", required=True, description="File to analyze"),
                ToolParameter("extract", "boolean", description="Extract files", default=False)
            ]
        ))
        
        # Cloud & Container Security
        self.register_tool(Tool(
            name="prowler",
            category="cloud",
            description="AWS/Azure/GCP security assessment",
            command="prowler",
            parameters=[
                ToolParameter("provider", "string", description="Cloud provider (aws/azure/gcp)"),
                ToolParameter("check", "string", description="Specific check to run")
            ]
        ))
        
        self.register_tool(Tool(
            name="trivy",
            category="cloud",
            description="Container and IaC vulnerability scanner",
            command="trivy",
            parameters=[
                ToolParameter("target", "string", required=True, description="Container/image to scan"),
                ToolParameter("severity", "string", description="Severity level")
            ]
        ))
        
        self.register_tool(Tool(
            name="kube-hunter",
            category="cloud",
            description="Kubernetes penetration testing",
            command="kube-hunter",
            parameters=[
                ToolParameter("pod", "boolean", description="Run as pod", default=False)
            ]
        ))
        
        # CTF & Forensics
        self.register_tool(Tool(
            name="volatility",
            category="ctf",
            description="Advanced memory forensics framework",
            command="volatility",
            parameters=[
                ToolParameter("dump_file", "string", required=True, description="Memory dump path"),
                ToolParameter("profile", "string", required=True, description="OS profile"),
                ToolParameter("plugin", "string", description="Plugin to run")
            ]
        ))
        
        self.register_tool(Tool(
            name="foremost",
            category="ctf",
            description="File carving and data recovery",
            command="foremost",
            parameters=[
                ToolParameter("file", "string", required=True, description="File to carve"),
                ToolParameter("output_dir", "string", description="Output directory")
            ]
        ))
        
        self.register_tool(Tool(
            name="steghide",
            category="ctf",
            description="Steganography detection and extraction",
            command="steghide",
            parameters=[
                ToolParameter("file", "string", required=True, description="Stego file"),
                ToolParameter("password", "string", description="Passphrase")
            ]
        ))
        
        # OSINT Tools
        self.register_tool(Tool(
            name="theHarvester",
            category="osint",
            description="Email and subdomain harvesting from multiple sources",
            command="theHarvester",
            parameters=[
                ToolParameter("domain", "string", required=True, description="Target domain"),
                ToolParameter("sources", "string", description="Sources to search")
            ]
        ))
        
        self.register_tool(Tool(
            name="shodan",
            category="osint",
            description="Internet-connected device search",
            command="shodan",
            parameters=[
                ToolParameter("query", "string", required=True, description="Search query"),
                ToolParameter("limit", "integer", description="Result limit", default=10)
            ]
        ))

        # Additional Network Tools
        network_tools = [
            ("fierce", "DNS reconnaissance and zone transfer testing"),
            ("dnsenum", "DNS information gathering and subdomain brute forcing"),
            ("autorecon", "Comprehensive automated reconnaissance"),
            ("responder", "LLMNR, NBT-NS and MDNS poisoner"),
            ("netexec", "Network service exploitation framework"),
            ("enum4linux-ng", "Advanced SMB enumeration"),
            ("smbmap", "SMB share enumeration and exploitation"),
            ("arp-scan", "Network discovery using ARP requests"),
            ("nbtscan", "NetBIOS name scanning and enumeration"),
            ("rpcclient", "RPC enumeration and null session testing")
        ]
        for name, desc in network_tools:
            self.register_tool(Tool(name=name, category="network", description=desc, command=name, parameters=[ToolParameter("target", "string", required=True)]))

        # Additional Web Tools
        web_tools = [
            ("dirsearch", "Advanced directory and file discovery"),
            ("httpx", "Fast HTTP probing and technology detection"),
            ("hakrawler", "Fast web endpoint discovery and crawling"),
            ("gau", "Get All URLs from multiple sources"),
            ("waybackurls", "Historical URL discovery from Wayback Machine"),
            ("nikto", "Web server vulnerability scanner"),
            ("wpscan", "WordPress security scanner"),
            ("arjun", "HTTP parameter discovery"),
            ("paramspider", "Parameter mining from web archives"),
            ("x8", "Hidden parameter discovery"),
            ("jaeles", "Advanced vulnerability scanning"),
            ("dalfox", "Advanced XSS vulnerability scanning"),
            ("wafw00f", "Web application firewall fingerprinting"),
            ("testssl", "SSL/TLS configuration testing"),
            ("sslscan", "SSL/TLS cipher suite enumeration"),
            ("sslyze", "Fast SSL/TLS configuration analyzer"),
            ("whatweb", "Web technology identification"),
            ("jwt-tool", "JSON Web Token testing"),
            ("commix", "Command injection exploitation tool"),
            ("nosqlmap", "NoSQL injection testing"),
            ("tplmap", "Server-side template injection exploitation")
        ]
        for name, desc in web_tools:
            self.register_tool(Tool(name=name, category="web", description=desc, command=name, parameters=[ToolParameter("url", "string", required=True)]))

        # Additional Cloud Tools
        cloud_tools = [
            ("scout-suite", "Multi-cloud security auditing"),
            ("cloudmapper", "AWS network visualization"),
            ("pacu", "AWS exploitation framework"),
            ("clair", "Container vulnerability analysis"),
            ("kube-bench", "CIS Kubernetes benchmark checker"),
            ("docker-bench-security", "Docker security assessment"),
            ("falco", "Runtime security monitoring"),
            ("checkov", "Infrastructure as code security scanning"),
            ("terrascan", "Infrastructure security scanner"),
            ("cloudsploit", "Cloud security scanning")
        ]
        for name, desc in cloud_tools:
            self.register_tool(Tool(name=name, category="cloud", description=desc, command=name, parameters=[ToolParameter("target", "string", required=True)]))

        # Additional Binary Tools
        binary_tools = [
            ("gdb-peda", "Python Exploit Development Assistance for GDB"),
            ("gdb-gef", "GDB Enhanced Features"),
            ("ropgadget", "ROP/JOP gadget finder"),
            ("ropper", "ROP gadget finder"),
            ("one-gadget", "Find one-shot RCE gadgets"),
            ("checksec", "Binary security property checker"),
            ("readelf", "ELF file analyzer"),
            ("xxd", "Hex dump utility"),
            ("pwntools", "CTF framework and exploit development"),
            ("angr", "Binary analysis platform"),
            ("upx", "Executable packer/unpacker")
        ]
        for name, desc in binary_tools:
            self.register_tool(Tool(name=name, category="binary", description=desc, command=name, parameters=[ToolParameter("binary", "string", required=True)]))

        # Additional CTF & Forensics
        ctf_tools = [
            ("volatility3", "Next-generation memory forensics"),
            ("photorec", "File recovery software"),
            ("testdisk", "Disk partition recovery"),
            ("stegsolve", "Steganography analysis tool"),
            ("zsteg", "PNG/BMP steganography detection"),
            ("outguess", "Universal steganographic tool"),
            ("exiftool", "Metadata reader/writer"),
            ("scalpel", "File carving tool"),
            ("bulk_extractor", "Feature extraction tool"),
            ("autopsy", "Digital forensics platform")
        ]
        for name, desc in ctf_tools:
            self.register_tool(Tool(name=name, category="ctf", description=desc, command=name, parameters=[ToolParameter("file", "string", required=True)]))

        logger.info(f"Registered {len(self.tools)} tools")
    
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
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                timeout=5
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
