# Installation Guide - Skyfall v7.0

Detailed installation instructions for Skyfall AI MCP v7.0

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Python Installation](#python-installation)
3. [Security Tools Installation](#security-tools-installation)
4. [Configuration](#configuration)
5. [Running the Server](#running-the-server)
6. [Verification](#verification)
7. [Docker Setup](#docker-setup)
8. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+, Kali Linux 2021+)
- **Python**: 3.8+
- **Memory**: 4GB RAM (8GB+ recommended)
- **Disk**: 10GB (20GB+ with tools)
- **Network**: Internet connection for tool installation

### Supported Platforms
- ✅ Ubuntu 20.04 LTS / 22.04 LTS
- ✅ Debian 10+
- ✅ Kali Linux 2021+
- ✅ Raspberry Pi OS (with limitations)
- ✅ Docker / Docker Compose
- ✅ Windows WSL2 + Ubuntu

### Recommended Setup
- **OS**: Kali Linux (comes with most tools pre-installed)
- **CPU**: Intel i7 / AMD Ryzen 5+ (or equivalent)
- **Memory**: 16GB RAM
- **Storage**: SSD (NVMe recommended)

---

## Python Installation

### Step 1: Update System

```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### Step 2: Install Python 3.11

```bash
# Install Python and pip
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip

# Set as default (optional)
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
```

### Step 3: Create Virtual Environment

```bash
# Navigate to project directory
cd skyfall-mcp

# Create virtual environment
python3.11 -m venv venv

# Activate it
source venv/bin/activate
# On Windows: venv\Scripts\activate
```

### Step 4: Upgrade pip and setuptools

```bash
pip install --upgrade pip setuptools wheel
```

### Step 5: Install Python Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

---

## Security Tools Installation

### Essential Tools Installation

#### Network & Reconnaissance

```bash
# Nmap and variants
sudo apt-get install -y nmap zenmap

# DNS tools
sudo apt-get install -y dnsmasq dnsutils bind9-utils

# HTTP tools
sudo apt-get install -y curl wget httpie netcat-openbsd

# Samba tools
sudo apt-get install -y smbclient samba-common-bin
```

#### Subdomain & OSINT Tools

```bash
# Go-based tools installation (requires Go 1.18+)
# Install Go first if not present
sudo apt-get install -y golang-go

# Create Go workspace
mkdir -p ~/go/bin
export PATH=$PATH:~/go/bin

# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install amass
go install -v github.com/OWASP/Amass/v3/cmd/amass@latest

# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Add Go bin to PATH permanently
echo "export PATH=$PATH:$(go env GOPATH)/bin" >> ~/.bashrc
source ~/.bashrc
```

#### Web Application Testing

```bash
# Gobuster
sudo apt-get install -y gobuster

# Nikto
sudo apt-get install -y nikto

# SQLMap
sudo apt-get install -y sqlmap

# WPScan
# From source or gem
sudo gem install wpscan  # If Ruby is installed
# OR from apt
sudo apt-get install -y wpscan

# FFuf
go install -v github.com/ffuf/ffuf@latest
```

#### Password Cracking

```bash
# John the Ripper
sudo apt-get install -y john

# Hashcat (requires GPU support)
sudo apt-get install -y hashcat

# Hydra
sudo apt-get install -y hydra

# Medusa
sudo apt-get install -y medusa
```

#### Binary Analysis & Reverse Engineering

```bash
# GDB and debugging tools
sudo apt-get install -y gdb gdbserver

# Radare2
sudo apt-get install -y radare2

# Binwalk
sudo apt-get install -y binwalk

# Ghidra (requires Java)
sudo apt-get install -y default-jdk
# Download from: https://github.com/NationalSecurityAgency/ghidra/releases
# Extract and add to PATH

# Volatility
pip install volatility3
```

#### Cloud & Container Tools

```bash
# Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Kubernetes tools
sudo apt-get install -y kubectl

# Trivy (vulnerability scanner)
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

#### Browser Requirements

```bash
# Chrome for browser agent
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt-get update
sudo apt-get install -y google-chrome-stable

# Chrome Driver (for Selenium)
sudo apt-get install -y chromium-chromedriver
# OR download from: https://chromedriver.chromium.org/
```

### Verification

Check if tools are installed:

```bash
# Create verification script
cat > verify_tools.sh << 'EOF'
#!/bin/bash
echo "=== Skyfall Tool Verification ==="

tools=(
    "nmap" "masscan" "curl" "wget"
    "subfinder" "nuclei" "gobuster" "nikto"
    "sqlmap" "john" "hashcat" "hydra"
    "gdb" "radare2" "binwalk"
    "docker" "docker-compose" "trivy"
    "python3" "pip3"
)

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (NOT FOUND)"
    fi
done
EOF

chmod +x verify_tools.sh
./verify_tools.sh
```

---

## Configuration

### Environment Setup

Create `.env` file:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Server Configuration
SKYFALL_PORT=8888
SKYFALL_HOST=0.0.0.0
SKYFALL_AUTH_ENABLED=false

# Cache Settings
SKYFALL_CACHE_SIZE=1000
SKYFALL_CACHE_TTL=3600

# Command Execution
COMMAND_TIMEOUT=300

# Debug Mode
DEBUG_MODE=0
```

### API Key Generation (if auth enabled)

```bash
# Start server first
python server_enhanced.py

# In another terminal, generate key
curl -X POST http://localhost:8888/api/auth/keys \
  -H "Content-Type: application/json" \
  -d '{"app_name": "my-app"}'

# Response:
# {
#   "key": "sk_xxxxxxxxxxxxxxxxxxxx",
#   "app_name": "my-app",
#   "created": "2024-01-01T00:00:00.000000"
# }
```

---

## Running the Server

### Development Mode

```bash
# Activate virtual environment
source venv/bin/activate

# Run with debug
python server_enhanced.py --debug

# Or on specific port
python server_enhanced.py --port 9999 --debug
```

### Production Mode

```bash
# Using Gunicorn (install if needed: pip install gunicorn)
gunicorn -w 4 -b 0.0.0.0:8888 server_enhanced:app

# Or use supervisor for process management
# Configure in /etc/supervisor/conf.d/skyfall.conf
```

### Background Execution

```bash
# Using nohup
nohup python server_enhanced.py > server.log 2>&1 &

# Using screen
screen -S skyfall
python server_enhanced.py

# Then: Ctrl+A+D to detach, screen -r skyfall to reattach
```

---

## Verification

### Test Server Health

```bash
# Check if server is running
curl http://localhost:8888/health

# Response should show:
# {
#   "status": "healthy",
#   "timestamp": "...",
#   "system": {...},
#   "tools": {...},
#   "application": {...}
# }
```

### Test Command Execution

```bash
# Without authentication
curl -X POST http://localhost:8888/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello"}'

# With authentication
curl -X POST http://localhost:8888/api/command \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_xxxxxxxxxxxxxxxxxxxx" \
  -d '{"command": "nmap -h"}'
```

### List Tools

```bash
# List all available tools
curl -X POST http://localhost:8888/api/tools/list \
  -H "X-API-Key: sk_xxxxxxxxxxxxxxxxxxxx"
```

---

## Docker Setup

### Build Docker Image

```bash
# Build
docker build -t skyfall-mcp:latest .

# Run
docker run -p 8888:8888 skyfall-mcp:latest
```

### Docker Compose

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f skyfall-mcp

# Check status
docker-compose ps
```

### Environment Variables for Docker

Create `.env.docker`:

```bash
SKYFALL_PORT=8888
SKYFALL_AUTH_ENABLED=true
SKYFALL_CACHE_SIZE=2000
SKYFALL_CACHE_TTL=3600
```

Then:

```bash
docker-compose --env-file .env.docker up -d
```

---

## Troubleshooting

### Python Module Errors

**Issue**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

### Port Already in Use

**Issue**: `OSError: [Errno 98] Address already in use`

**Solution**:
```bash
# Find process on port 8888
sudo lsof -i :8888

# Kill the process
sudo kill -9 <PID>

# Or use different port
python server_enhanced.py --port 9999
```

### Tool Not Found

**Issue**: `Command not found: nmap`

**Solution**:
```bash
# Check if installed
which nmap

# Install if missing
sudo apt-get install -y nmap

# Verify PATH
echo $PATH
```

### Browser Agent Issues

**Issue**: `Chrome not found` or `WebDriver error`

**Solution**:
```bash
# Install Chrome
sudo apt-get install -y google-chrome-stable

# Install Chrome Driver
sudo apt-get install -y chromium-chromedriver

# Or manually download:
# https://chromedriver.chromium.org/
# https://googlechromelabs.github.io/chrome-for-testing/
```

### Permission Errors

**Issue**: `Permission denied` errors

**Solution**:
```bash
# Give execute permissions
chmod +x server_enhanced.py

# Or run with python
python server_enhanced.py

# For system-wide tools, use sudo (carefully!)
sudo python server_enhanced.py
```

### Memory Issues

**Issue**: `MemoryError` or server crashes

**Solution**:
```bash
# Check available memory
free -h

# Reduce cache size
export SKYFALL_CACHE_SIZE=500

# Or limit Python memory
python -c "import resource; resource.setrlimit(resource.RLIMIT_AS, (2000000000, 2000000000))"
python server_enhanced.py
```

### Connection Refused

**Issue**: `ConnectionRefusedError` when connecting from AI client

**Solution**:
```bash
# Check if server is running
curl http://localhost:8888/health

# Check firewall
sudo ufw status
sudo ufw allow 8888

# Check server logs
tail -f server.log
```

---

## Next Steps

1. **Configure AI Client** - Set up Claude, GPT, or other MCP client
2. **Run Tests** - Execute test suite: `make test`
3. **Create API Keys** - Generate authentication keys if needed
4. **Start Testing** - Begin security assessments

For questions or issues, visit: [GitHub Issues](https://github.com/sunilv3/skyfall/issues)
