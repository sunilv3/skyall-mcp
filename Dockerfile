# Skyfall AI Agents v7.0 - Full Kali Linux Headless Suite
FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install Kali Headless Metapackage (100+ tools)
# This includes nmap, metasploit, john, sqlmap, hydra, etc.
# Install core security tools
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    nikto \
    gobuster \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    golang \
    # Install Project Discovery tools (Critical for Bug Bounty)
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/OWASP/Amass/v3/...@latest \
    # Move go binaries to path
    && cp /root/go/bin/* /usr/local/bin/ \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt || \
    pip3 install --no-cache-dir flask requests python-dotenv psutil pandas dnspython openpyxl

# Expose the dashboard port
EXPOSE 8888

# Command to run the Skyfall AI Server
# Binding to 0.0.0.0 is critical for Docker access
CMD ["python3", "skyfall_server.py", "--host", "0.0.0.0", "--port", "8888"]
