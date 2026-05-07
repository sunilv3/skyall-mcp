#!/usr/bin/env python3
"""
Notifier System for Skyfall AI v7.0
Sends real-time alerts to Discord, Slack, or Telegram
"""

import os
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class Notifier:
    """Handles external notifications for critical findings"""

    def __init__(self):
        self.discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL")
        self.telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        
        logger.info("Notifier system initialized")

    def send_alert(self, title: str, message: str, severity: str = "INFO"):
        """Send alert to all configured channels"""
        
        # Format message
        full_msg = f"🛡️ **[Skyfall AI Alert]**\n**Severity**: {severity}\n**Target**: {title}\n**Finding**: {message}"
        
        if self.discord_webhook:
            self._send_discord(full_msg, severity)
        
        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(full_msg)

    def _send_discord(self, message: str, severity: str):
        """Send message via Discord Webhook"""
        color = 0xFF0000 if severity in ["CRITICAL", "HIGH"] else 0xFFFF00
        
        payload = {
            "embeds": [{
                "title": "🚨 Security Finding Detected",
                "description": message,
                "color": color
            }]
        }
        
        try:
            requests.post(self.discord_webhook, json=payload, timeout=10)
            logger.info("Discord notification sent")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")

    def _send_telegram(self, message: str):
        """Send message via Telegram Bot API"""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            requests.post(url, json=payload, timeout=10)
            logger.info("Telegram notification sent")
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
