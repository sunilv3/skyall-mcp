import time
import logging
import os
import random
from typing import Optional, List

logger = logging.getLogger(__name__)

class ProxyManager:
    """Manages proxy rotation and integration for tools"""
    
    def __init__(self):
        self.proxies = self._load_proxies()
        self.rotation_interval = 10  # seconds
        self.last_rotation_time = 0
        self.current_proxy_index = 0
        self.enabled = os.environ.get("SKYFALL_PROXY_ENABLED", "false").lower() in ("1", "true", "yes", "y")
        
    def _load_proxies(self) -> List[str]:
        proxy_str = os.environ.get("SKYFALL_PROXIES", "")
        if proxy_str:
            return [p.strip() for p in proxy_str.split(",") if p.strip()]
        
        # Check for proxy list file
        proxy_file = "data/proxies.txt"
        if os.path.exists(proxy_file):
            try:
                with open(proxy_file, "r") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Failed to read proxy file: {e}")
        
        return []

    def get_current_proxy(self) -> Optional[str]:
        """Get the current proxy, rotating if necessary"""
        if not self.enabled or not self.proxies:
            return None
            
        now = time.time()
        if now - self.last_rotation_time > self.rotation_interval:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
            self.last_rotation_time = now
            logger.info(f"Proxy rotated to: {self.proxies[self.current_proxy_index]}")
            
        return self.proxies[self.current_proxy_index]

    def get_proxy_args(self, tool_name: str) -> List[str]:
        """Return proxy arguments for specific tools"""
        proxy = self.get_current_proxy()
        if not proxy:
            return []
            
        if tool_name == "nmap":
            # nmap supports socks4, http
            return ["--proxies", proxy]
        if tool_name in ["sqlmap", "nikto", "dirb", "gobuster", "ffuf", "nuclei", "dalfox"]:
            return ["--proxy", proxy]
        if tool_name == "curl":
            return ["-x", proxy]
            
        return []
