#!/usr/bin/env python3
"""
Intelligent Decision Engine for Skyfall AI MCP v7.0
Handles autonomous tool selection, parameter optimization, and attack chain discovery
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class IntelligentDecisionEngine:
    """The brain of Skyfall AI - analyzes targets and optimizes security workflows"""

    def __init__(self, tool_registry):
        """
        Initialize the decision engine
        
        Args:
            tool_registry: The ToolRegistry instance
        """
        self.tool_registry = tool_registry
        self.vuln_intelligence = {} # Placeholder for CVE/Intel data

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
        
        # Determine target type
        target_type = self._determine_target_type(target)
        
        # Select initial reconnaissance tools
        recon_tools = self._select_recon_tools(target_type)
        
        return {
            "target": target,
            "target_type": target_type,
            "recommended_strategy": self._get_strategy_description(target_type),
            "suggested_tools": recon_tools,
            "estimated_priority": "high" if target_type == "web" else "medium"
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
        Optimize tool parameters based on target context
        
        Args:
            tool_name: Name of the tool
            parameters: Initial parameters
            target_info: Information about the target (e.g., OS, tech stack)
            
        Returns:
            Optimized parameters
        """
        optimized = parameters.copy()
        
        # Example optimization: adjust nmap timing based on network speed
        if tool_name == "nmap":
            if "-T" not in optimized.get("additional_args", ""):
                optimized["additional_args"] = optimized.get("additional_args", "") + " -T4"
        
        # Example optimization: set wordlists for gobuster
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

    def _select_recon_tools(self, target_type: str) -> List[str]:
        """Suggest tools for initial phase"""
        if target_type == "web":
            return ["nuclei", "httpx", "gobuster"]
        if target_type == "domain":
            return ["amass", "subfinder", "nmap"]
        return ["nmap", "rustscan"]

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
