import threading
import logging
import time
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class MissionManager:
    """Manages active security missions and tracks their real-time progress"""
    
    def __init__(self):
        self.active_missions = {}
        self.lock = threading.Lock()

    def start_mission(self, target: str, tools: List[str]):
        mission_id = f"mission-{int(time.time())}"
        # Copy list to avoid mutating caller-owned tool selections during status updates.
        queued_tools = list(tools or [])
        with self.lock:
            self.active_missions[mission_id] = {
                "id": mission_id,
                "target": target,
                "status": "INITIALIZING",
                "current_tool": None,
                "completed_tools": [],
                "queued_tools": queued_tools,
                "start_time": datetime.now().isoformat(),
                "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] Mission initialized for {target}"]
            }
        return mission_id

    def update_status(self, mission_id: str, status: str, current_tool: str = None, log: str = None):
        with self.lock:
            if mission_id in self.active_missions:
                mission = self.active_missions[mission_id]
                mission["status"] = status
                if current_tool:
                    mission["current_tool"] = current_tool
                    if current_tool in mission["queued_tools"]:
                        mission["queued_tools"].remove(current_tool)
                if log:
                    mission["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {log}")

    def complete_tool(self, mission_id: str, tool_name: str):
        with self.lock:
            if mission_id in self.active_missions:
                self.active_missions[mission_id]["completed_tools"].append(tool_name)

    def get_status(self, mission_id: str) -> Dict:
        with self.lock:
            return self.active_missions.get(mission_id, {"status": "NOT_FOUND"})

    def list_active(self) -> List[Dict]:
        with self.lock:
            return list(self.active_missions.values())
