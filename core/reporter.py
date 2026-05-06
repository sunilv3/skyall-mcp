#!/usr/bin/env python3
"""
Reporting Engine for Skyfall AI v7.0
Generates professional security assessment reports
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class Reporter:
    """Generates human-readable reports from scan results"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self._ensure_dir()

    def _ensure_dir(self):
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_report(self, scan_data: Dict[str, Any]) -> str:
        """Generate a markdown report for a scan"""
        target = scan_data.get("target", "Unknown")
        timestamp = scan_data.get("timestamp", datetime.now().isoformat())
        findings = scan_data.get("findings", [])
        
        filename = f"Report_{target.replace('.', '_')}_{int(datetime.now().timestamp())}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        report_content = [
            f"# 🛡️ Security Assessment Report: {target}",
            f"**Date**: {timestamp}",
            f"**Platform**: Skyfall AI Agents v7.0",
            "\n## 📋 Summary",
            f"- **Target**: {target}",
            f"- **Findings Discovered**: {len(findings)}",
            f"- **Overall Risk Level**: {'CRITICAL' if any(f.get('severity') == 'CRITICAL' for f in findings) else 'MODERATE'}",
            "\n## 🔍 Detailed Findings"
        ]
        
        if not findings:
            report_content.append("\n*No significant vulnerabilities discovered during this mission.*")
        else:
            for i, vuln in enumerate(findings):
                report_content.append(f"\n### {i+1}. {vuln.get('title', 'Unknown Vulnerability')}")
                report_content.append(f"- **Severity**: {vuln.get('severity', 'UNKNOWN')}")
                report_content.append(f"- **Description**: {vuln.get('description', 'No description provided.')}")
                report_content.append(f"- **Remediation**: {vuln.get('remediation', 'Further investigation required.')}")
        
        report_content.append("\n---\n*Report generated automatically by Skyfall AI.*")
        
        try:
            with open(filepath, 'w') as f:
                f.write("\n".join(report_content))
            logger.info(f"Report generated: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return ""
