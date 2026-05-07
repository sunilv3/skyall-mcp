# Skyfall AI Agents v7.0 - Full Kali Linux Headless Suite
FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV GOPATH=/root/go
ENV PATH="$PATH:/root/go/bin:/root/.cargo/bin"

# ── LAYER 1: Kali Headless + system packages ────────────────────────
# kali-linux-headless gives us 100+ tools including:
#   nmap, metasploit, sqlmap, hydra, john, nikto, gobuster,
#   wafw00f, whatweb, enum4linux, masscan, commix, sslscan,
#   theHarvester, wpscan, ffuf, httpx, shodan, amass, nping
RUN apt-get update && apt-get install -y \
    kali-linux-headless \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    golang-go \
    cargo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── LAYER 2: Extra tools available in Kali repos ────────────────────
# These are NOT part of kali-linux-headless but ARE in the Kali repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    subfinder \
    nuclei \
    arjun \
    xsstrike \
    dnsx \
    paramspider \
    crlfuzz \
    feroxbuster \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── LAYER 3: Go-based tools (not in Kali repos) ─────────────────────
RUN go install -v github.com/hahwul/dalfox/v2@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# ── LAYER 4: Cargo-based tools ──────────────────────────────────────
RUN cargo install rustscan \
    && cp /root/.cargo/bin/rustscan /usr/local/bin/ 2>/dev/null || true

# ── LAYER 5: Git & Pip based tools (no reliable apt/pip packages) ──────
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
    && pip3 install --no-cache-dir --break-system-packages /opt/ghauri \
    && ln -sf /usr/local/bin/ghauri /usr/bin/ghauri

RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/corsy \
    && echo '#!/bin/bash\npython3 /opt/corsy/corsy.py "$@"' > /usr/local/bin/corsy \
    && chmod +x /usr/local/bin/corsy

RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/linkfinder/requirements.txt \
    && echo '#!/bin/bash\npython3 /opt/linkfinder/linkfinder.py "$@"' > /usr/local/bin/linkfinder \
    && chmod +x /usr/local/bin/linkfinder

RUN git clone --depth 1 https://github.com/defparam/smuggler.git /opt/smuggler \
    && ln -sf /opt/smuggler/smuggler.py /usr/local/bin/smuggler \
    && chmod +x /opt/smuggler/smuggler.py

# ── Fix: amass wrapper tries to download libpostal data ──────────────
# Creating this marker directory prevents the wrapper from calling
# the nonexistent 'libpostal_data' command.
RUN mkdir -p /usr/share/libpostal/transliteration

# Create working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt || \
    pip3 install --no-cache-dir --break-system-packages flask requests python-dotenv psutil pandas dnspython openpyxl

# Expose the dashboard port
EXPOSE 8888

# Command to run the Skyfall AI Server
# Binding to 0.0.0.0 is critical for Docker access
CMD ["python3", "skyfall_server.py", "--host", "0.0.0.0", "--port", "8888"]
