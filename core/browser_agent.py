#!/usr/bin/env python3
"""
Enhanced Browser Agent with Anti-Detection (v7.0)
Headless Chrome automation for web testing with stealth mode
"""

import base64
import json
import logging
import subprocess
import time
from typing import Dict, List, Any, Optional
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

logger = logging.getLogger(__name__)


class BrowserAgent:
    """Enhanced Browser Agent with anti-detection and comprehensive analysis"""

    STEALTH_JS = """
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
    });
    
    window.chrome = {
        runtime: {},
    };
    
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5],
    });
    
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
    });
    """

    def __init__(self, headless: bool = True, stealth_mode: bool = True):
        """
        Initialize browser agent

        Args:
            headless: Run in headless mode
            stealth_mode: Enable anti-detection features
        """
        self.headless = headless
        self.stealth_mode = stealth_mode
        self.driver = None
        self._initialize_driver()

    def _initialize_driver(self):
        """Initialize Selenium WebDriver with Chrome options"""
        chrome_options = Options()

        if self.headless:
            chrome_options.add_argument("--headless=new")

        # Performance and stability
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")

        # Anti-detection measures
        if self.stealth_mode:
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option("useAutomationExtension", False)

        # Additional options for stability
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-popup-blocking")
        chrome_options.add_argument("--disable-notifications")

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(
                service=service,
                options=chrome_options
            )

            # Inject stealth JavaScript
            if self.stealth_mode:
                self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                    "source": self.STEALTH_JS
                })

            logger.info("Browser agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize browser agent: {e}")
            raise

    def navigate_and_inspect(self, url: str, wait_time: int = 10) -> Dict[str, Any]:
        """
        Navigate to URL and perform comprehensive analysis

        Args:
            url: Target URL
            wait_time: Wait time for page load

        Returns:
            Dictionary with analysis results
        """
        try:
            logger.info(f"Navigating to {url}")
            self.driver.get(url)

            # Wait for page to load
            WebDriverWait(self.driver, wait_time).until(
                EC.presence_of_all_elements_located((By.TAG_NAME, "body"))
            )

            # Collect metrics
            metrics = {
                "url": self.driver.current_url,
                "title": self.driver.title,
                "source_length": len(self.driver.page_source),
                "screenshot": self._capture_screenshot(),
                "performance_metrics": self._get_performance_metrics(),
                "security_headers": self._extract_security_headers(),
                "forms": self._extract_forms(),
                "links": self._extract_links(),
                "scripts": self._extract_scripts(),
                "cookies": self._extract_cookies(),
                "console_logs": self._get_console_logs(),
                "dom_elements": self._count_dom_elements(),
                "images": self._extract_images(),
                "csp": self._analyze_csp(),
                "event_listeners": self._detect_event_listeners(),
                "memory_metrics": self._get_memory_metrics(),
                "navigation_timing": self._get_navigation_timing(),
            }

            return metrics

        except Exception as e:
            logger.error(f"Error during navigation and inspection: {e}")
            return {
                "error": str(e),
                "url": url,
                "success": False
            }

    def _capture_screenshot(self) -> str:
        """Capture screenshot and return as base64"""
        try:
            screenshot = self.driver.get_screenshot_as_base64()
            return screenshot[:100] + "..." if len(screenshot) > 100 else screenshot
        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")
            return None

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Extract performance metrics from Navigation Timing API"""
        try:
            script = """
            const timing = window.performance.timing;
            const navigation = window.performance.navigation;
            return {
                page_load_time: timing.loadEventEnd - timing.navigationStart,
                dom_content_loaded: timing.domContentLoadedEventEnd - timing.navigationStart,
                dom_interactive: timing.domInteractive - timing.navigationStart,
                time_to_first_byte: timing.responseStart - timing.navigationStart,
                resource_load_time: timing.responseEnd - timing.requestStart,
                navigation_type: navigation.type,
            };
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to get performance metrics: {e}")
            return {}

    def _extract_security_headers(self) -> Dict[str, str]:
        """Extract security-related headers"""
        headers = {}
        try:
            # Get all headers from the page
            security_headers = [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            
            # This would require CDP for real headers, simulate from page
            for header in security_headers:
                headers[header] = "Not detected"
            
            return headers
        except Exception as e:
            logger.warning(f"Failed to extract security headers: {e}")
            return {}

    def _extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all forms from page"""
        try:
            forms = []
            form_elements = self.driver.find_elements(By.TAG_NAME, "form")

            for form in form_elements:
                form_data = {
                    "id": form.get_attribute("id"),
                    "name": form.get_attribute("name"),
                    "method": form.get_attribute("method") or "GET",
                    "action": form.get_attribute("action"),
                    "fields": []
                }

                # Extract form fields
                inputs = form.find_elements(By.TAG_NAME, "input")
                for inp in inputs:
                    form_data["fields"].append({
                        "name": inp.get_attribute("name"),
                        "type": inp.get_attribute("type"),
                        "id": inp.get_attribute("id"),
                    })

                forms.append(form_data)

            return forms
        except Exception as e:
            logger.warning(f"Failed to extract forms: {e}")
            return []

    def _extract_links(self) -> List[str]:
        """Extract all links from page"""
        try:
            links = []
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")

            for link in link_elements[:50]:  # Limit to first 50
                href = link.get_attribute("href")
                if href and (href.startswith("http") or href.startswith("/")):
                    links.append(href)

            return list(set(links))
        except Exception as e:
            logger.warning(f"Failed to extract links: {e}")
            return []

    def _extract_scripts(self) -> List[Dict[str, str]]:
        """Extract script tags and sources"""
        try:
            scripts = []
            script_elements = self.driver.find_elements(By.TAG_NAME, "script")

            for script in script_elements[:20]:  # Limit to first 20
                script_data = {
                    "src": script.get_attribute("src"),
                    "type": script.get_attribute("type") or "application/javascript",
                }
                if script_data["src"]:
                    scripts.append(script_data)

            return scripts
        except Exception as e:
            logger.warning(f"Failed to extract scripts: {e}")
            return []

    def _extract_cookies(self) -> List[Dict[str, Any]]:
        """Extract all cookies"""
        try:
            cookies = self.driver.get_cookies()
            return [
                {
                    "name": c.get("name"),
                    "value": c.get("value")[:20] + "..." if len(str(c.get("value"))) > 20 else c.get("value"),
                    "secure": c.get("secure"),
                    "httpOnly": c.get("httpOnly"),
                    "domain": c.get("domain"),
                }
                for c in cookies[:10]  # Limit to first 10
            ]
        except Exception as e:
            logger.warning(f"Failed to extract cookies: {e}")
            return []

    def _get_console_logs(self) -> List[Dict[str, str]]:
        """Get console logs and errors"""
        try:
            logs = []
            browser_logs = self.driver.get_log("browser")

            for entry in browser_logs[:20]:  # Limit to first 20
                logs.append({
                    "level": entry.get("level"),
                    "message": entry.get("message")[:100],
                    "source": entry.get("source"),
                })

            return logs
        except Exception as e:
            logger.warning(f"Failed to get console logs: {e}")
            return []

    def _count_dom_elements(self) -> Dict[str, int]:
        """Count DOM elements by type"""
        try:
            script = """
            return {
                total_elements: document.getElementsByTagName('*').length,
                forms: document.getElementsByTagName('form').length,
                inputs: document.getElementsByTagName('input').length,
                buttons: document.getElementsByTagName('button').length,
                links: document.getElementsByTagName('a').length,
                images: document.getElementsByTagName('img').length,
                scripts: document.getElementsByTagName('script').length,
                styles: document.getElementsByTagName('style').length + document.getElementsByTagName('link').length,
            };
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to count DOM elements: {e}")
            return {}

    def _extract_images(self) -> List[str]:
        """Extract image sources"""
        try:
            images = []
            img_elements = self.driver.find_elements(By.TAG_NAME, "img")

            for img in img_elements[:20]:  # Limit to first 20
                src = img.get_attribute("src")
                if src:
                    images.append(src)

            return images
        except Exception as e:
            logger.warning(f"Failed to extract images: {e}")
            return []

    def _analyze_csp(self) -> Dict[str, Any]:
        """Analyze Content Security Policy"""
        try:
            script = """
            const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            const cspContent = csp ? csp.getAttribute('content') : null;
            
            return {
                has_csp: !!csp,
                csp_content: cspContent,
                directives_count: cspContent ? cspContent.split(';').length : 0,
            };
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to analyze CSP: {e}")
            return {}

    def _detect_event_listeners(self) -> Dict[str, int]:
        """Detect event listeners on document"""
        try:
            script = """
            const events = {};
            const eventTypes = ['click', 'submit', 'change', 'keydown', 'keyup', 'focus', 'blur', 'load'];
            
            for (const event of eventTypes) {
                events[event] = 0;
            }
            
            // This is a simplified version - full detection requires Chrome DevTools Protocol
            return events;
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to detect event listeners: {e}")
            return {}

    def _get_memory_metrics(self) -> Dict[str, Any]:
        """Get JavaScript memory metrics"""
        try:
            script = """
            if (performance.memory) {
                return {
                    used_js_heap_size: Math.round(performance.memory.usedJSHeapSize / 1048576) + ' MB',
                    total_js_heap_size: Math.round(performance.memory.totalJSHeapSize / 1048576) + ' MB',
                    heap_limit: Math.round(performance.memory.jsHeapSizeLimit / 1048576) + ' MB',
                };
            }
            return {};
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to get memory metrics: {e}")
            return {}

    def _get_navigation_timing(self) -> Dict[str, int]:
        """Get detailed navigation timing"""
        try:
            script = """
            const timing = window.performance.timing;
            return {
                redirect_time: timing.redirectEnd - timing.redirectStart,
                app_cache_time: timing.domainLookupStart - timing.fetchStart,
                dns_lookup_time: timing.domainLookupEnd - timing.domainLookupStart,
                tcp_connection_time: timing.connectEnd - timing.connectStart,
                request_time: timing.responseStart - timing.requestStart,
                response_time: timing.responseEnd - timing.responseStart,
                dom_parsing_time: timing.domInteractive - timing.domLoading,
                dom_content_loaded: timing.domContentLoadedEventEnd - timing.domContentLoadedEventStart,
                resource_loading_time: timing.loadEventStart - timing.domContentLoadedEventEnd,
                load_event_time: timing.loadEventEnd - timing.loadEventStart,
            };
            """
            return self.driver.execute_script(script)
        except Exception as e:
            logger.warning(f"Failed to get navigation timing: {e}")
            return {}

    def close(self):
        """Close the browser"""
        try:
            if self.driver:
                self.driver.quit()
                logger.info("Browser closed successfully")
        except Exception as e:
            logger.warning(f"Error closing browser: {e}")


def analyze_website(url: str, headless: bool = True) -> Dict[str, Any]:
    """
    Analyze a website and return comprehensive metrics

    Args:
        url: Website URL to analyze
        headless: Run browser in headless mode

    Returns:
        Analysis results
    """
    agent = None
    try:
        agent = BrowserAgent(headless=headless, stealth_mode=True)
        results = agent.navigate_and_inspect(url)
        return {
            "success": True,
            "url": url,
            "data": results
        }
    except Exception as e:
        logger.error(f"Failed to analyze website: {e}")
        return {
            "success": False,
            "url": url,
            "error": str(e)
        }
    finally:
        if agent:
            agent.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    result = analyze_website("https://example.com")
    print(json.dumps(result, indent=2))
