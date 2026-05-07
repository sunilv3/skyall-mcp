#!/usr/bin/env python3
"""
History Manager for Skyfall AI v7.0
Persists scan results and findings to disk
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class HistoryManager:
    """Manages scan history and report persistence"""

    def __init__(self, history_file: str = "data/scan_history.json"):
        self.history_file = history_file
        self._ensure_data_dir()
        self.history = self._load_history()

    def _ensure_data_dir(self):
        Path(self.history_file).parent.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.history_file):
            with open(self.history_file, 'w') as f:
                json.dump([], f)

    def _load_history(self) -> List[Dict]:
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load history: {e}")
            return []

    def save_scan(
        self,
        target: str,
        agent: str,
        findings: List[Dict] = None,
        status: str = "completed",
        analysis: str = "",
        execution_details: List[Dict] = None,
    ):
        """Save a new scan result to history"""
        scan_entry = {
            "id": f"scan-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "agent": agent,
            "findings_count": len(findings) if findings else 0,
            "findings": findings or [],
            "status": status,
            "analysis": analysis,
            "execution_details": execution_details or []
        }
        self.history.insert(0, scan_entry)
        # Keep only last 100 scans
        self.history = self.history[:100]
        
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
            logger.info(f"Saved scan history for {target}")
        except Exception as e:
            logger.error(f"Failed to save history: {e}")

    def get_history(self) -> List[Dict]:
        """Get all scan history"""
        return self.history

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan by ID"""
        original_len = len(self.history)
        self.history = [s for s in self.history if s["id"] != scan_id]
        if len(self.history) < original_len:
            try:
                with open(self.history_file, 'w') as f:
                    json.dump(self.history, f, indent=2)
                logger.info(f"Deleted scan {scan_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to save history after deletion: {e}")
        return False
