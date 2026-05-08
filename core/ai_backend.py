import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from openai import OpenAI
import httpx

from core.proxy_manager import ProxyManager
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class AIBackend:
    """Unified interface for AI models to power security agents"""

    def __init__(self):
        load_dotenv()
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY")
        self.nvidia_key = os.environ.get("NVIDIA_API_KEY")
        self.google_key = os.environ.get("GOOGLE_API_KEY")
        self.oss_mode = os.environ.get("SKYFALL_OSS_MODE", "false").lower() in ("1", "true", "yes", "y")
        self.oss_base_url = os.environ.get("SKYFALL_OSS_BASE_URL", "http://127.0.0.1:11434/v1")
        self.oss_api_key = os.environ.get("SKYFALL_OSS_API_KEY", "ollama")
        self.oss_model = os.environ.get("SKYFALL_OSS_MODEL", "llama3.1:8b")
        
        self.default_model = os.environ.get("SKYFALL_MODEL", "openai/gpt-4o")
        self.proxy_manager = ProxyManager()
        
        # Build proxy dict for httpx
        self.http_proxy = None
        current_proxy = self.proxy_manager.get_current_proxy()
        if current_proxy:
            self.http_proxy = {"http://": current_proxy, "https://": current_proxy}
            logger.info(f"AI Backend: Using proxy {current_proxy}")
        
        # Initialize clients
        self.oss_client = None
        if self.oss_mode:
            self.oss_client = OpenAI(
                base_url=self.oss_base_url,
                api_key=self.oss_api_key,
                http_client=httpx.Client(proxies=self.http_proxy) if self.http_proxy else None
            )

        self.openrouter_client = None
        if self.openrouter_key:
            self.openrouter_client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.openrouter_key,
                default_headers={
                    "HTTP-Referer": "https://github.com/sunilv3/skyfall",
                    "X-Title": "Skyfall AI"
                },
                http_client=httpx.Client(proxies=self.http_proxy) if self.http_proxy else None
            )
            
        self.nvidia_client = None
        if self.nvidia_key:
            self.nvidia_client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=self.nvidia_key
            )
            
        mode = "OSS" if self.oss_mode else "Cloud"
        logger.info(f"AI Backend initialized in {mode} mode with model: {self.default_model if not self.oss_mode else self.oss_model}")

    def query(self, prompt: str, system_prompt: str = "You are a professional cybersecurity expert.") -> str:
        """Query the AI model with automatic failover for free models"""
        if self.oss_client:
            try:
                logger.info(f"Attempting query with OSS model: {self.oss_model}")
                return self._query_client(self.oss_client, self.oss_model, prompt, system_prompt)
            except Exception as e:
                logger.warning(f"OSS model failed, falling back to cloud providers: {e}")

        models_to_try = [self.default_model]
        
        # Define high-quality free/low-cost fallbacks
        fallbacks = [
            "google/gemini-2.0-flash-lite-preview-02-05:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "deepseek/deepseek-chat:free",
            "google/gemini-flash-1.5:free",
            "mistralai/mistral-7b-instruct:free",
            "nvidia/llama-3.1-nemotron-70b-instruct"
        ]
        
        # If using a paid model that might fail (like gpt-4o), we want these as safety nets
        for f in fallbacks:
            if f not in models_to_try:
                models_to_try.append(f)

        
        # Add local Gemini as a final robust fallback if key exists
        if self.google_key:
            models_to_try.append("google/gemini-direct")

        last_error = None
        for model in models_to_try:
            try:
                logger.info(f"Attempting query with model: {model}")
                
                # Special case for direct Google API
                if model == "google/gemini-direct" and self.google_key:
                    return self._query_google(prompt, system_prompt)
                
                if self.nvidia_client and "nvidia" in model.lower():
                    return self._query_client(self.nvidia_client, model, prompt, system_prompt)
                elif self.openrouter_client:
                    return self._query_client(self.openrouter_client, model, prompt, system_prompt)
                elif self.google_key and "google" in model.lower():
                    return self._query_google(prompt, system_prompt)
            except Exception as e:
                logger.warning(f"Model {model} failed: {e}")
                last_error = e
                continue
        
        return f"All models failed. Last error: {str(last_error)}"

    def _query_client(self, client: OpenAI, model: str, prompt: str, system_prompt: str) -> str:
        """Universal query for OpenAI-compatible clients"""
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            timeout=90
        )
        return response.choices[0].message.content

    def analyze_vulnerability(self, tool_output: str) -> Dict[str, Any]:
        """Use AI to analyze tool output for vulnerabilities and Zero-Day patterns"""
        prompt = f"""
        You are a world-class Zero-Day researcher. Analyze the following tool output for security vulnerabilities.
        
        GOAL: Identify CRITICAL and HIGH severity findings, including potential Zero-Days.
        
        Focus Areas:
        1. Injection Points: SQLi, XSS, SSRF, Command Injection.
        2. Logic Flaws: Broken Access Control, IDOR, sensitive data exposure.
        3. Configuration Issues: Weak SSL, exposed secrets, verbose errors.
        4. Zero-Day Indicators: Unusual status codes, timing anomalies, undocumented headers/params.
        
        CRITICAL: If you find ANY vulnerability, you MUST provide:
        - A clear Title and Severity.
        - The exact Evidence (line or snippet from output).
        - A functional Exploit Payload or proof-of-concept command.
        - Remediation instructions.
        
        Tool Output:
        {tool_output}
        """
        response = self.query(prompt, "You are a professional security auditor specialized in exploit development.")
        
        return {
            "analysis": response,
            "confidence_score": 0.95,
            "timestamp": datetime.now().isoformat(),
            "next_steps": ["Verify exploitability of identified findings", "Correlate with existing CVE database"]
        }

    def analyze_owasp_top10(self, tool_output: str, target: str = "") -> Dict[str, Any]:
        """Generate OWASP Top 10-aligned assessment summary with remediation focus."""
        prompt = f"""
        You are a senior application security reviewer.
        Analyze the scan output for authorized security testing and map findings to OWASP Top 10 (2021):
        A01 Broken Access Control
        A02 Cryptographic Failures
        A03 Injection
        A04 Insecure Design
        A05 Security Misconfiguration
        A06 Vulnerable and Outdated Components
        A07 Identification and Authentication Failures
        A08 Software and Data Integrity Failures
        A09 Security Logging and Monitoring Failures
        A10 Server-Side Request Forgery

        Target: {target}

        Required output format:
        1) Executive Summary (risk posture in 3-5 bullets)
        2) OWASP Findings Table:
           - Category (A01-A10)
           - Evidence from output
           - Severity (Critical/High/Medium/Low/Info)
           - Confidence (High/Medium/Low)
           - Remediation
        3) Validation Checklist (manual verification steps, safe/defensive only)
        4) Prioritized Remediation Plan (Immediate, Near-term, Long-term)
        5) False Positive Notes and Unknowns

        Do NOT provide offensive exploit payloads or attack instructions.

        Tool Output:
        {tool_output}
        """
        response = self.query(prompt, "You are a defensive AppSec expert generating compliance-friendly OWASP reports.")
        return {
            "analysis": response,
            "framework": "OWASP Top 10 (2021)",
            "confidence_score": 0.9,
            "timestamp": datetime.now().isoformat(),
            "next_steps": ["Validate high-risk findings", "Open remediation tickets by OWASP category"]
        }

    def _query_google(self, prompt: str, system_prompt: str) -> str:
        """Query Gemini via Google AI API (robust version)"""
        import requests
        try:
            # Use gemini-1.5-flash for faster response and better availability on free tier
            # but keep it configurable or fall back to pro if needed. 
            # The original code used gemini-1.5-pro.
            model_id = "gemini-1.5-flash"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={self.google_key}"
            
            data = {
                "contents": [{"parts": [{"text": f"{system_prompt}\n\n{prompt}"}]}],
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ],
                "generationConfig": {
                    "temperature": 0.3,
                    "topP": 0.8,
                    "topK": 40,
                    "maxOutputTokens": 2048,
                }
            }
            
            response = requests.post(url, json=data, timeout=60)
            res_json = response.json()
            
            if "candidates" in res_json and len(res_json["candidates"]) > 0:
                candidate = res_json["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    return candidate["content"]["parts"][0]["text"]
                elif "finishReason" in candidate:
                    return f"Gemini failed: Generation finished with reason {candidate['finishReason']}"
            
            if "promptFeedback" in res_json and "blockReason" in res_json["promptFeedback"]:
                return f"Gemini blocked the request due to safety filters: {res_json['promptFeedback']['blockReason']}. (Consider using a different model or rephrasing for authorized testing)."
            
            if "error" in res_json:
                return f"Gemini API Error: {res_json['error'].get('message', 'Unknown error')}"
                
            return f"Gemini failed: No candidates returned. Response: {json.dumps(res_json)[:200]}"
            
        except Exception as e:
            logger.error(f"Gemini Query Exception: {str(e)}")
            return f"Gemini failed: {str(e)}"



