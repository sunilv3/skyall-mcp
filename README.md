# Skyall MCP - Kali Server

**Skyall MCP Kali Server** is a lightweight API bridge that connects MCP clients (e.g: Claude Desktop or 5ire) to an API server that allows executing commands on a Linux terminal.

This MCP can run terminal commands and interact with web applications using:

- Dirb
- enum4linux
- gobuster
- Hydra
- John the Ripper
- Metasploit-Framework
- Nikto
- Nmap
- sqlmap
- WPScan
- wafw00f — WAF detection  
- dalfox / XSStrike — XSS scanning  
- subfinder / amass — Subdomain enumeration  
- nuclei — Vulnerability scanning  
- ffuf — Web fuzzing  
- commix — Command injection  
- ghauri — Advanced SQL injection  
- corsy — CORS misconfiguration scanner  
- crlfuzz — CRLF injection scanner  
- smuggler — HTTP request smuggling detection  
- katana — Web crawler  
- gau — URL fetching from archives  
- arjun — Parameter discovery  
- paramspider — Parameter extraction  
- And raw command execution  

---

## 👨‍💻 Created By

**Skyall (sunilv3)**  
https://github.com/sunilv3  

---

## 🔍 Use Case

- Connect MCP with AI models (OpenAI, Claude, DeepSeek, Ollama, etc.)
- Execute commands on Kali Linux via API
- Automate:
  - CTF solving  
  - Recon  
  - Exploitation  
- Send custom commands like curl, nmap, ffuf, etc.

---

## 🚀 Features

- 🧠 AI Integration  
- 🖥️ Command Execution API  
- 🕸️ Web Interaction Support  
- 🔐 Offensive Security Focus  
- 🛡️ 40+ Security Tools Included  

---

## 🛠️ Installation

### 🐧 Linux / Kali

```bash
git clone https://github.com/sunilv3/skyall-mcp.git
cd skyall-mcp

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python3 server.py
```

---

### 🪟 Windows

```powershell
git clone https://github.com/sunilv3/skyall-mcp.git
cd skyall-mcp

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt

python server.py
```

---

### 🍎 macOS

```bash
git clone https://github.com/sunilv3/skyall-mcp.git
cd skyall-mcp

python3 -m venv .venv
source .venv/bin/activate

pip3 install -r requirements.txt

python3 server.py
```

---

## 🔌 MCP Client Setup

### Local Connection (Same Machine)

```bash
python3 client.py --server http://127.0.0.1:5000
```

---

### Remote Connection (Recommended via SSH)

```bash
# Terminal 1
ssh -L 5000:localhost:5000 user@LINUX_IP

# Terminal 2
python3 client.py --server http://127.0.0.1:5000
```

---

## ⚙️ Claude Desktop Configuration

### Config File Locations

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

---

### 🪟 Windows Example

```json
{
  "mcpServers": {
    "skyall-kali-server": {
      "command": "python",
      "args": ["C:\\Users\\YOUR_USERNAME\\skyall-mcp\\client.py", "--server", "http://127.0.0.1:5000"]
    }
  }
}
```

---

### 🍎 macOS / 🐧 Linux Example

```json
{
  "mcpServers": {
    "skyall-kali-server": {
      "command": "python3",
      "args": ["/home/YOUR_USERNAME/skyall-mcp/client.py", "--server", "http://127.0.0.1:5000"]
    }
  }
}
```

---

## 🧩 5ire Desktop Configuration

Simply add an MCP using:

```bash
python3 /absolute/path/to/client.py --server http://LINUX_IP:5000
```

5ire will automatically generate the required configuration files.

---

## ⚠️ Disclaimer

This project is intended **only for educational and ethical security testing purposes**.

Unauthorized use, exploitation, or malicious activity is strictly prohibited.  
The author assumes no responsibility for misuse.

---
