#!/usr/bin/env python3
"""
LRU Cache System for Skyfall AI MCP v7.0
Provides intelligent result caching with TTL support
"""

import json
import logging
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class LRUCache:
    """Least Recently Used Cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """
        Initialize LRU cache
        
        Args:
            max_size: Maximum number of items in cache
            ttl_seconds: Time-to-live for cache entries (0 = no expiration)
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict[str, Dict] = OrderedDict()
        self.hits = 0
        self.misses = 0
        logger.info(f"Initialized LRU Cache: max_size={max_size}, ttl={ttl_seconds}s")
    
    def _make_key(self, command: str, params: Optional[Dict] = None) -> str:
        """Create cache key from command and parameters"""
        if params:
            param_str = json.dumps(params, sort_keys=True)
            return f"{command}:{param_str}"
        return command
    
    def _is_expired(self, entry: Dict) -> bool:
        """Check if cache entry is expired"""
        if self.ttl_seconds == 0:
            return False
        
        created_at = entry.get("created_at", 0)
        age = time.time() - created_at
        return age > self.ttl_seconds
    
    def get(self, command: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Get value from cache
        
        Args:
            command: Command string
            params: Optional parameters dictionary
            
        Returns:
            Cached result or None if not found/expired
        """
        key = self._make_key(command, params)
        
        if key not in self.cache:
            self.misses += 1
            return None
        
        entry = self.cache[key]
        
        if self._is_expired(entry):
            del self.cache[key]
            self.misses += 1
            return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        self.hits += 1
        
        return entry.get("result")
    
    def set(self, command: str, result: Any, params: Optional[Dict] = None):
        """
        Set value in cache
        
        Args:
            command: Command string
            result: Result to cache
            params: Optional parameters dictionary
        """
        key = self._make_key(command, params)
        
        # Remove if exists to update position
        if key in self.cache:
            del self.cache[key]
        
        # Add entry
        self.cache[key] = {
            "result": result,
            "created_at": time.time()
        }
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        
        # Evict oldest if over capacity
        while len(self.cache) > self.max_size:
            evicted_key = next(iter(self.cache))
            del self.cache[evicted_key]
            logger.debug(f"Evicted cache entry: {evicted_key}")
    
    def clear(self):
        """Clear all cache entries"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        logger.info("Cache cleared")
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2),
            "ttl_seconds": self.ttl_seconds
        }
    
    def get_size_mb(self) -> float:
        """Get approximate cache size in MB"""
        total_bytes = sum(len(json.dumps(entry)) for entry in self.cache.values())
        return total_bytes / (1024 * 1024)
