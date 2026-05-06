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

    def save_scan(self, target: str, agent: str, findings: List[Dict], status: str = "completed"):
        """Save a new scan result to history"""
        scan_entry = {
            "id": f"scan-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "agent": agent,
            "findings_count": len(findings),
            "findings": findings,
            "status": status
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
