#!/usr/bin/env python3
"""
Comprehensive Health Monitor (v7.0)
System metrics and tool availability monitoring
"""

import logging
import os
import psutil
import shutil
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Monitor system health and tool availability"""

    TOOL_CATEGORIES = {
        "network": [
            "nmap", "rustscan", "masscan", "amass", "subfinder",
            "fierce", "dnsenum", "autorecon", "theharvester",
            "responder", "netexec", "enum4linux-ng", "arp-scan",
            "nbtscan", "smbmap", "rpcclient"
        ],
        "web": [
            "gobuster", "feroxbuster", "dirsearch", "ffuf", "dirb",
            "httpx", "katana", "nikto", "sqlmap", "wpscan",
            "arjun", "paramspider", "dalfox", "wafw00f", "testssl.sh"
        ],
        "authentication": [
            "hydra", "john", "hashcat", "medusa", "patator",
            "crackmapexec", "evil-winrm", "hash-identifier"
        ],
        "binary": [
            "gdb", "radare2", "binwalk", "ghidra", "checksec",
            "strings", "objdump", "volatility3", "ropper"
        ],
        "cloud": [
            "prowler", "scout-suite", "trivy", "kube-hunter",
            "kube-bench", "docker"
        ],
        "ctf": [
            "pwntools", "angr", "steghide", "exiftool",
            "foremost", "photorec"
        ],
        "osint": [
            "whois", "dig", "curl", "wget", "git",
            "jq", "grep", "sed"
        ]
    }

    @staticmethod
    def check_tool(tool_name: str) -> bool:
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None

    @classmethod
    def get_tool_availability(cls) -> Dict[str, Any]:
        """Get availability of all security tools"""
        availability = {}
        total_tools = 0
        available_tools = 0

        for category, tools in cls.TOOL_CATEGORIES.items():
            availability[category] = {
                "tools": {},
                "available": 0,
                "total": len(tools)
            }

            for tool in tools:
                is_available = cls.check_tool(tool)
                availability[category]["tools"][tool] = is_available
                total_tools += 1
                if is_available:
                    availability[category]["available"] += 1
                    available_tools += 1

            # Calculate percentage
            percentage = (availability[category]["available"] / len(tools) * 100) if tools else 0
            availability[category]["percentage"] = round(percentage, 1)

        availability["summary"] = {
            "total_tools": total_tools,
            "available_tools": available_tools,
            "percentage": round(available_tools / total_tools * 100, 1) if total_tools > 0 else 0
        }

        return availability

    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """Get system resource metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            disk = psutil.disk_usage('/')
            
            process_count = len(psutil.pids())
            boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            uptime_seconds = int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())
            
            return {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "load_average": {
                        "1_min": round(load_avg[0], 2),
                        "5_min": round(load_avg[1], 2),
                        "15_min": round(load_avg[2], 2)
                    }
                },
                "memory": {
                    "total_mb": round(memory.total / (1024 * 1024), 2),
                    "used_mb": round(memory.used / (1024 * 1024), 2),
                    "available_mb": round(memory.available / (1024 * 1024), 2),
                    "percent": memory.percent
                },
                "swap": {
                    "total_mb": round(swap.total / (1024 * 1024), 2),
                    "used_mb": round(swap.used / (1024 * 1024), 2),
                    "free_mb": round(swap.free / (1024 * 1024), 2),
                    "percent": swap.percent
                },
                "disk": {
                    "total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
                    "used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
                    "free_gb": round(disk.free / (1024 * 1024 * 1024), 2),
                    "percent": disk.percent
                },
                "processes": {
                    "count": process_count
                },
                "system": {
                    "boot_time": boot_time,
                    "uptime_seconds": uptime_seconds
                }
            }
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {}

    @staticmethod
    def get_application_metrics(cache_stats: Dict = None, telemetry: Dict = None,
                               process_count: int = 0) -> Dict[str, Any]:
        """Get application-specific metrics"""
        return {
            "cache": cache_stats or {"hits": 0, "misses": 0, "size": 0},
            "telemetry": telemetry or {"requests": 0, "errors": 0},
            "processes": {
                "active": process_count
            }
        }

    @classmethod
    def get_full_health(cls, cache_stats: Dict = None, telemetry: Dict = None,
                       process_count: int = 0) -> Dict[str, Any]:
        """Get complete health status"""
        try:
            import time
            start_time = time.time()
            
            health = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "system": cls.get_system_metrics(),
                "tools": cls.get_tool_availability(),
                "application": cls.get_application_metrics(cache_stats, telemetry, process_count),
                "response_time_ms": round((time.time() - start_time) * 1000, 2)
            }
            
            return health
        except Exception as e:
            logger.error(f"Failed to get full health status: {e}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    monitor = HealthMonitor()
    import json
    
    # Example usage
    health = monitor.get_full_health()
    print(json.dumps(health, indent=2))
