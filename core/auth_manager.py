#!/usr/bin/env python3
"""
Authentication Manager for Skyfall AI MCP v7.0
Handles API key-based authentication with file persistence
"""

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Manages API key authentication for Skyfall MCP Server"""
    
    def __init__(self, key_file: str = "data/api_keys.json", enabled: bool = True):
        """
        Initialize authentication manager
        
        Args:
            key_file: Path to store API keys
            enabled: Whether authentication is enabled
        """
        self.key_file = key_file
        self.enabled = enabled
        self.keys: Dict[str, Dict] = {}
        
        if self.enabled:
            self._ensure_key_file()
            self._load_keys()
            logger.info(f"Authentication enabled. Keys file: {key_file}")
        else:
            logger.info("Authentication disabled")
    
    def _ensure_key_file(self):
        """Ensure key file and directory exist"""
        key_path = Path(self.key_file)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not key_path.exists():
            key_path.write_text(json.dumps({}, indent=2))
    
    def _load_keys(self):
        """Load API keys from file"""
        try:
            with open(self.key_file, 'r') as f:
                self.keys = json.load(f)
            logger.info(f"Loaded {len(self.keys)} API keys")
        except Exception as e:
            logger.error(f"Failed to load API keys: {e}")
            self.keys = {}
    
    def _save_keys(self):
        """Save API keys to file"""
        try:
            self._ensure_key_file()
            with open(self.key_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save API keys: {e}")
    
    def generate_key(self, name: str = None) -> Tuple[str, str]:
        """
        Generate a new API key
        
        Args:
            name: Optional name for the key
            
        Returns:
            Tuple of (key_id, key_secret)
        """
        if not self.enabled:
            logger.warning("Authentication is disabled")
            return None, None
        
        key_id = secrets.token_urlsafe(16)
        key_secret = secrets.token_urlsafe(32)
        
        self.keys[key_id] = {
            "secret": key_secret,
            "name": name or f"Key {len(self.keys) + 1}",
            "created": str(Path(self.key_file).stat().st_mtime if Path(self.key_file).exists() else 0),
            "active": True
        }
        
        self._save_keys()
        logger.info(f"Generated new API key: {name or 'unnamed'}")
        
        return key_id, key_secret
    
    def verify_key(self, key_id: str, key_secret: str) -> bool:
        """
        Verify an API key
        
        Args:
            key_id: Key ID
            key_secret: Key secret
            
        Returns:
            True if key is valid and active
        """
        if not self.enabled:
            return True
        
        if key_id not in self.keys:
            logger.warning(f"Invalid key ID: {key_id}")
            return False
        
        key_data = self.keys[key_id]
        
        if not key_data.get("active", False):
            logger.warning(f"Key {key_id} is inactive")
            return False
        
        if key_data.get("secret") != key_secret:
            logger.warning(f"Invalid key secret for {key_id}")
            return False
        
        return True
    
    def verify_header(self, auth_header: str) -> bool:
        """
        Verify authorization header (Bearer or ApiKey format)
        
        Args:
            auth_header: Authorization header value
            
        Returns:
            True if valid
        """
        if not self.enabled:
            return True
        
        if not auth_header:
            return False
        
        parts = auth_header.split()
        if len(parts) != 2:
            return False
        
        scheme, credentials = parts
        
        # Support both "Bearer key_id:key_secret" and "ApiKey key_id:key_secret"
        if scheme.lower() not in ["bearer", "apikey"]:
            return False
        
        if ":" not in credentials:
            return False
        
        key_id, key_secret = credentials.split(":", 1)
        return self.verify_key(key_id, key_secret)
    
    def list_keys(self, mask_secrets: bool = True) -> List[Dict]:
        """
        List all API keys
        
        Args:
            mask_secrets: Whether to mask secret values
            
        Returns:
            List of key information
        """
        result = []
        for key_id, key_data in self.keys.items():
            entry = {
                "key_id": key_id,
                "name": key_data.get("name", "Unnamed"),
                "active": key_data.get("active", False),
                "created": key_data.get("created", "Unknown")
            }
            
            if not mask_secrets:
                entry["secret"] = key_data.get("secret", "")
            else:
                # Show only first 4 and last 4 characters
                secret = key_data.get("secret", "")
                if len(secret) > 8:
                    entry["secret"] = f"{secret[:4]}...{secret[-4:]}"
                else:
                    entry["secret"] = "***"
            
            result.append(entry)
        
        return result
    
    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke an API key
        
        Args:
            key_id: Key ID to revoke
            
        Returns:
            True if successfully revoked
        """
        if key_id not in self.keys:
            return False
        
        self.keys[key_id]["active"] = False
        self._save_keys()
        logger.info(f"Revoked key: {key_id}")
        
        return True
    
    def get_status(self) -> Dict:
        """
        Get authentication status
        
        Returns:
            Dictionary with status information
        """
        return {
            "enabled": self.enabled,
            "total_keys": len(self.keys),
            "active_keys": sum(1 for k in self.keys.values() if k.get("active", False)),
            "key_file": self.key_file
        }
