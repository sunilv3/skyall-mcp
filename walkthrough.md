# Skyfall AI Agents v7.0 - Global Setup Walkthrough 🌍

Follow these steps to deploy your AI-powered cybersecurity platform on any operating system.

---

## 🐋 Option 1: Docker (Recommended - Best for All OS)
This method is the fastest and ensures all 140+ Kali Linux tools are pre-installed.

### Prerequisites
- Install **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux).

### Steps
1. **Clone/Open Project**: Open your project folder in a terminal.
2. **Configure API Keys**: Open `.env` and add your OpenRouter, Google, or NVIDIA keys.
3. **Build & Launch**:
   ```bash
   docker-compose up --build -d
   ```
4. **Access Dashboard**: Open your browser to **[http://localhost:8888/dashboard](http://localhost:8888/dashboard)**.

---

## 🪟 Option 2: Windows (Native)
### Prerequisites
- **Python 3.10+** installed.
- **Git** installed.

### Steps
1. **Run Setup**: Double-click `build.bat`. This will:
   - Create a Virtual Environment (`.venv`).
   - Install all Python dependencies.
   - Launch the `skyfallbabies.py` menu.
2. **Manual Start**:
   ```powershell
   python skyfall_server.py
   ```
3. **Access Dashboard**: Open **[http://localhost:8888/dashboard](http://localhost:8888/dashboard)**.

---

## 🐧 Option 3: Linux (Native)
### Prerequisites
- **Python 3.10+**.
- Recommended: **Kali Linux** (for tool compatibility).

### Steps
1. **Setup Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Start Server**:
   ```bash
   python3 skyfall_server.py
   ```
3. **Access Dashboard**: Open **[http://localhost:8888/dashboard](http://localhost:8888/dashboard)**.

---

## 🍎 Option 4: macOS (Native)
### Prerequisites
- **Homebrew** installed.
- **Python 3.10+**.

### Steps
1. **Setup Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Start Server**:
   ```bash
   python3 skyfall_server.py
   ```
3. **Access Dashboard**: Open **[http://localhost:8888/dashboard](http://localhost:8888/dashboard)**.

---

## 🎮 How to use the Dashboard
1. **Initiate Scan**: Go to the **Mission Control** tab, enter a domain, and click **INITIATE SCAN**.
2. **Monitor**: Watch the **Live Intelligence Feed** to see the AI's thought process.
3. **Tool Registry**: Switch to the **Tool Registry** tab to see all 151 available security tools.
4. **History**: Check **Scan History** to review results from previous missions.

---
**Stay Safe. Stay Anonymous. Skyfall AI.**
