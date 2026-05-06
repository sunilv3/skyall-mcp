#!/usr/bin/env python3
"""
Process Manager for Skyfall AI MCP v7.0
Manages long-running security tool processes with monitoring
"""

import logging
import os
import psutil
import signal
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ProcessManager:
    """Manages and monitors system processes"""
    
    def __init__(self):
        """Initialize process manager"""
        self.processes: Dict[int, Dict] = {}
        logger.info("Initialized Process Manager")
    
    def register_process(self, pid: int, command: str, tool_name: str = None) -> bool:
        """
        Register a new process
        
        Args:
            pid: Process ID
            command: Command string
            tool_name: Name of tool running
            
        Returns:
            True if successfully registered
        """
        try:
            process = psutil.Process(pid)
            self.processes[pid] = {
                "pid": pid,
                "command": command,
                "tool_name": tool_name or "unknown",
                "created_time": datetime.now().isoformat(),
                "status": process.status()
            }
            logger.info(f"Registered process {pid}: {command}")
            return True
        except Exception as e:
            logger.error(f"Failed to register process {pid}: {e}")
            return False
    
    def unregister_process(self, pid: int) -> bool:
        """
        Unregister a process
        
        Args:
            pid: Process ID
            
        Returns:
            True if found and removed
        """
        if pid in self.processes:
            del self.processes[pid]
            logger.info(f"Unregistered process {pid}")
            return True
        return False
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Get detailed information about a process
        
        Args:
            pid: Process ID
            
        Returns:
            Process information or None if not found
        """
        if pid not in self.processes:
            return None
        
        try:
            process = psutil.Process(pid)
            
            info = self.processes[pid].copy()
            info.update({
                "status": process.status(),
                "cpu_percent": process.cpu_percent(interval=0.1),
                "memory_mb": process.memory_info().rss / (1024 * 1024),
                "num_threads": process.num_threads(),
                "returncode": process.returncode,
                "children": len(process.children()),
                "running": process.is_running()
            })
            
            return info
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} no longer exists")
            self.unregister_process(pid)
            return None
        except Exception as e:
            logger.error(f"Error getting info for process {pid}: {e}")
            return None
    
    def list_processes(self) -> List[Dict]:
        """
        List all managed processes
        
        Returns:
            List of process information
        """
        result = []
        dead_pids = []
        
        for pid in list(self.processes.keys()):
            info = self.get_process_info(pid)
            if info:
                result.append(info)
            else:
                dead_pids.append(pid)
        
        # Clean up dead processes
        for pid in dead_pids:
            self.unregister_process(pid)
        
        return result
    
    def terminate_process(self, pid: int, timeout: int = 5) -> bool:
        """
        Terminate a process gracefully, then forcefully if needed
        
        Args:
            pid: Process ID
            timeout: Timeout for graceful termination
            
        Returns:
            True if successfully terminated
        """
        try:
            process = psutil.Process(pid)
            
            # Try graceful termination
            process.terminate()
            try:
                process.wait(timeout=timeout)
                logger.info(f"Terminated process {pid} gracefully")
                self.unregister_process(pid)
                return True
            except psutil.TimeoutExpired:
                # Force kill if graceful didn't work
                process.kill()
                process.wait()
                logger.warning(f"Force killed process {pid}")
                self.unregister_process(pid)
                return True
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            self.unregister_process(pid)
            return False
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False
    
    def get_dashboard(self) -> Dict:
        """
        Get dashboard with system and process statistics
        
        Returns:
            Dashboard data
        """
        try:
            processes = self.list_processes()
            
            total_cpu = sum(p.get("cpu_percent", 0) for p in processes)
            total_memory = sum(p.get("memory_mb", 0) for p in processes)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "system": {
                    "cpu_percent": psutil.cpu_percent(interval=1),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage("/").percent
                },
                "processes": {
                    "count": len(processes),
                    "total_cpu_percent": round(total_cpu, 2),
                    "total_memory_mb": round(total_memory, 2),
                    "active": processes
                }
            }
        except Exception as e:
            logger.error(f"Error generating dashboard: {e}")
            return {"error": str(e)}
    
    def get_stats(self) -> Dict:
        """Get process statistics"""
        processes = self.list_processes()
        
        return {
            "total_processes": len(processes),
            "running": sum(1 for p in processes if p.get("running", False)),
            "stopped": len(processes) - sum(1 for p in processes if p.get("running", False)),
            "by_tool": self._group_by_tool(processes)
        }
    
    def _group_by_tool(self, processes: List[Dict]) -> Dict[str, int]:
        """Group processes by tool name"""
        grouped = {}
        for process in processes:
            tool = process.get("tool_name", "unknown")
            grouped[tool] = grouped.get(tool, 0) + 1
        return grouped
