import random
import time
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class EvasionManager:
    """Handles stealth and WAF/CDN evasion strategies"""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    ]

    def __init__(self):
        self.stealth_enabled = True

    def get_stealth_headers(self) -> Dict[str, str]:
        """Generate headers to mimic a real browser and bypass basic WAFs"""
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        }

    def apply_jitter(self, min_sec: float = 1.0, max_sec: float = 3.0):
        """Apply random delay to avoid rate-limiting and timing analysis"""
        if self.stealth_enabled:
            delay = random.uniform(min_sec, max_sec)
            logger.debug(f"Stealth Mode: Applying jitter delay of {delay:.2f}s")
            time.sleep(delay)

    def get_evasion_args(self, tool_name: str) -> List[str]:
        """Return tool-specific evasion arguments (e.g., nmap fragmentation)"""
        if tool_name == "nmap":
            return ["-f", "--mtu", "24", "--data-length", "16", "--source-port", "53"]
        if tool_name == "gobuster":
            return ["--delay", "500ms", "--random-agent"]
        return []
