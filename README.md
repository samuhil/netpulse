# 📡 NetPulse — Cybernetic Protocol Stream & Security Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)](package.json)
[![Web Audio API](https://img.shields.io/badge/Audio-Tactile_Sonar-orange.svg)](js/sonarAudio.js)
[![GitHub Pages](https://img.shields.io/badge/Deployment-GitHub_Pages-brightgreen.svg)](.github/workflows/deploy.yml)
[![Architecture](https://img.shields.io/badge/Architecture-Vanilla_ES6%2B-yellow.svg)](js/app.js)

> An interactive, cyberpunk-themed network protocol analyzer, live packet stream dissector, Wireshark-grade hex viewer, and security analysis sandbox.

---

## ⚡ Key Features

```
[ Client ] ---> [ Gateway Router ] ---> [ WAF / Firewall ] ---> [ CDN Edge ] ---> [ Origin API ]
    |                    |                      |                     |                  |
    +-----> Live Traveling Energy Pulses (DNS, TCP, TLS 1.3, HTTP/2, SYN Floods) <-------+
```

### 1. 🌐 Real-Time Packet Stream & Protocol Dissector
* Captures and parses live streams across OSI layers:
  * **Layer 3**: IPv4 / IPv6 (TTL, Checksum, Flags, Header Length)
  * **Layer 4**: TCP (SYN, ACK, FIN, PSH, RST, Sequence Numbers) & UDP
  * **Layer 7**: DNS queries, TLS 1.3 Handshake (SNI inspection), HTTP/2 REST headers
* Interactive filtering by **Protocol**, **Free-text search**, or **Threat Signature**.

### 2. 💾 Wireshark-Grade Hex Dump & ASCII Inspector
* Full 16-byte formatted Hex view with memory offsets (`0000`, `0010`, ...).
* Color-coded separation between **Header Bytes** (Cyan) and **Data Payload** (Green).
* Expandable OSI protocol tree displaying Ethernet II frames, IP headers, and application records.

### 3. 🛡️ Attack Vector & Security Anomaly Simulator
* **🟢 Normal Production Traffic**: Healthy mix of DNS queries, TLS 1.3 handshakes, and API endpoints.
* **🔴 SYN Flood (DDoS Attack)**: Simulates hundreds of spoofed half-open connections targeting port 443.
* **🟡 Port Scan (Reconnaissance)**: Replicates an aggressive Nmap service probe across open ports.
* **🟣 DNS Tunneling (Data Exfiltration)**: Detects high-entropy base64 subdomain queries used for covert data leaking.

### 4. 🧰 Cryptographic & Security Toolbox
* **⚡ Shannon Information Entropy Calculator**:
  * Calculates byte randomness ($H = -\sum p \log_2 p$) on a scale of 0.0 to 8.0 bits.
  * Classifies plaintext (2.5–3.8) vs. packed binaries/malware shellcode (> 7.1).
* **🔑 JWT Cyber Inspector**:
  * Decodes Base64Url Header and Payload claims.
  * Audits signatures and flags vulnerabilities (e.g., `alg: "none"` auth bypass, expired tokens).
* **🔄 Multi-Format Payload Converter**:
  * Real-time transformations: Base64 ↔ Hex ↔ URL Encode ↔ ROT13.
* **🚀 Custom Packet Crafter & Injector**:
  * Craft custom IP headers, TCP flags, and payloads, then inject them directly into the live topology stream!

### 5. 🔊 Tactile Cyber Sonar (Web Audio API)
* Procedural audio telemetry:
  * Crisp high-frequency blips for incoming packets.
  * Tactical siren alarm when threats or firewall intercepts occur.
  * Zero external sound files needed.

---

## 🚀 Quick Start

This project has **zero build dependencies**. It runs in any modern web browser.

### Option A: Open directly
Open [`index.html`](index.html) in your browser.

### Option B: Local Web Server
```bash
# Python
python -m http.server 8080

# Or Node.js
npx serve .
```
Navigate to `http://localhost:8080`.

---

## 📁 Repository Structure

```
netpulse/
├── .github/
│   └── workflows/
│       └── deploy.yml          # Automatic GitHub Pages CI/CD
├── css/
│   └── style.css               # Tactical cyberpunk HUD & CRT scanlines
├── js/
│   ├── app.js                  # Main controller & UI state
│   ├── hexViewer.js            # Hex dump & OSI tree dissector
│   ├── networkCanvas.js        # Dynamic interactive topology map
│   ├── packetEngine.js         # Protocol generator & packet dissector
│   ├── securityTools.js        # Entropy, JWT, and payload converter
│   └── sonarAudio.js           # Procedural Web Audio telemetry
├── .gitignore                  # Git ignore definitions
├── index.html                  # Cyberpunk HUD interface
├── LICENSE                     # MIT License
├── package.json                # Project manifest
└── README.md                   # Documentation & specifications
```

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
