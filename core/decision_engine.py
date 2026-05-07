#!/usr/bin/env python3
"""
Intelligent Decision Engine for Skyfall AI MCP v7.0
Handles autonomous tool selection, parameter optimization, and attack chain discovery
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple

from core.evasion_manager import EvasionManager

logger = logging.getLogger(__name__)

class IntelligentDecisionEngine:
    """The brain of Skyfall AI - analyzes targets and optimizes security workflows"""

    def __init__(self, tool_registry):
        """
        Initialize the decision engine
        """
        self.tool_registry = tool_registry
        self.evasion_manager = EvasionManager()
        self.vuln_intelligence = {} 

    def analyze_target(self, target: str, context: Dict = None) -> Dict[str, Any]:
        """
        Analyze a target and recommend a testing strategy
        
        Args:
            target: The target (IP, domain, URL)
            context: Additional context (e.g., prior scan results)
            
        Returns:
            Recommended strategy and tool selection
        """
        logger.info(f"Analyzing target: {target}")
        
        context = context or {}

        # Determine target type
        target_type = self._determine_target_type(target)
        scan_profile = str(context.get("scan_profile", "balanced")).lower()
        agent_profile = str(context.get("agent_profile", "bugbounty")).lower()
        owasp_mode = bool(context.get("owasp_top10_mode", False))

        # Select phase tools based on profile and agent type
        recon_tools = self._select_recon_tools(target_type, scan_profile, agent_profile, owasp_mode)
        
        return {
            "target": target,
            "target_type": target_type,
            "recommended_strategy": self._get_strategy_description(target_type),
            "suggested_tools": recon_tools,
            "estimated_priority": "high" if target_type == "web" else "medium",
            "scan_profile": scan_profile,
            "agent_profile": agent_profile,
            "owasp_top10_mode": owasp_mode
        }

    def select_tools(self, target: str, objectives: List[str]) -> List[Dict]:
        """
        Select specific tools based on objectives
        
        Args:
            target: The target string
            objectives: List of goals (e.g., "enumerate subdomains", "scan for SQLi")
            
        Returns:
            List of tool configurations
        """
        selected = []
        for objective in objectives:
            tool_match = self._match_objective_to_tool(objective)
            if tool_match:
                selected.append(tool_match)
        
        return selected

    def optimize_parameters(self, tool_name: str, parameters: Dict, target_info: Dict = None) -> Dict:
        """
        Optimize tool parameters based on target context and stealth requirements
        """
        optimized = parameters.copy()
        
        # Apply stealth/evasion arguments
        evasion_args = self.evasion_manager.get_evasion_args(tool_name)
        if evasion_args:
            current_args = optimized.get("additional_args", "")
            optimized["additional_args"] = f"{current_args} {' '.join(evasion_args)}".strip()
            logger.info(f"Stealth Mode: Applied evasion parameters for {tool_name}")

        # Standard optimizations
        if tool_name == "nmap":
            if "-T" not in optimized.get("additional_args", ""):
                optimized["additional_args"] = optimized.get("additional_args", "") + " -T4"
        
        if tool_name == "gobuster" and not optimized.get("wordlist"):
            optimized["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
            
        return optimized

    def discover_attack_chain(self, findings: List[Dict]) -> List[Dict]:
        """
        Discover potential attack chains from scan findings
        
        Args:
            findings: List of vulnerabilities or discoveries
            
        Returns:
            Proposed attack paths
        """
        # Logic to correlate findings (e.g., open port -> service version -> CVE -> exploit)
        chains = []
        for finding in findings:
            if finding.get("type") == "port_open" and finding.get("service"):
                chains.append({
                    "path": f"Exploit {finding['service']} on port {finding['port']}",
                    "confidence": 0.8,
                    "next_step": "cve_lookup"
                })
        return chains

    def _determine_target_type(self, target: str) -> str:
        """Identify if target is IP, domain, or URL"""
        if target.startswith("http"):
            return "web"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return "network"
        if "." in target:
            return "domain"
        return "unknown"

    def _select_recon_tools(
        self,
        target_type: str,
        scan_profile: str = "balanced",
        agent_profile: str = "bugbounty",
        owasp_mode: bool = False,
    ) -> List[str]:
        """Suggest tools for initial phase with profile-aware depth."""
        base = []
        if target_type == "web":
            base = ["nuclei", "httpx", "gobuster"]
        elif target_type == "domain":
            base = ["amass", "subfinder", "nmap"]
        else:
            base = ["nmap", "rustscan"]

        # Profile expansion controls scan depth and speed.
        if scan_profile == "fast":
            base = [t for t in base if t in ("httpx", "nuclei", "nmap", "subfinder", "rustscan")]
        elif scan_profile == "deep":
            if target_type == "web":
                base.extend(["whatweb", "nikto", "ffuf", "testssl", "sqlmap", "dalfox"])
            elif target_type == "domain":
                base.extend(["theHarvester", "dnsenum"])
            else:
                base.extend(["masscan"])

        # RedTeamer profile includes broader authorized assessment visibility.
        if agent_profile in ("redteamer", "red-teamer", "red_teamer"):
            if target_type == "web":
                base.extend(["wafw00f", "waybackurls", "gau", "commix", "sqlmap", "dalfox"])
            elif target_type == "domain":
                base.extend(["theHarvester", "fierce", "enum4linux"])
            else:
                base.extend(["masscan", "crackmapexec"])

        if owasp_mode and target_type == "web":
            # OWASP Top 10-focused stack for authorized web assessments.
            base.extend([
                "httpx", "whatweb", "nuclei", "nikto", "testssl", "wafw00f",
                "gobuster", "ffuf", "waybackurls", "gau"
            ])

        # preserve order, remove duplicates
        seen = set()
        ordered = []
        for tool in base:
            if tool not in seen:
                seen.add(tool)
                ordered.append(tool)
        return ordered

    def _get_strategy_description(self, target_type: str) -> str:
        strategies = {
            "web": "Comprehensive Web Application Security Assessment",
            "domain": "Full External Surface Reconnaissance",
            "network": "Network Port and Service Discovery",
            "unknown": "General Reconnaissance"
        }
        return strategies.get(target_type, "General Reconnaissance")

    def _match_objective_to_tool(self, objective: str) -> Optional[Dict]:
        objective = objective.lower()
        if "subdomain" in objective:
            return {"tool": "amass", "reason": "Superior subdomain discovery"}
        if "port" in objective or "scan" in objective:
            return {"tool": "nmap", "reason": "Standard for port discovery"}
        if "directory" in objective or "file" in objective:
            return {"tool": "gobuster", "reason": "Fast directory brute forcing"}
        if "sqli" in objective or "sql injection" in objective:
            return {"tool": "sqlmap", "reason": "Automated SQLi exploitation"}
        return None
