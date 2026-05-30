# 0x-Hunt 🎯

An autonomous bug bounty hunting agent with an agentic AI loop, built to run entirely from Termux on Android.

## Features

- **Agentic Loop** — AI-driven recon and scanning pipeline powered by Groq (llama-3.3-70b-versatile)
- **Terminal TUI** — Full ANSI-rendered interface with 5 switchable tabs, no browser required
- **Session Persistence** — Crash recovery with resumable hunt sessions
- **VPN-Aware** — Detects and validates VPN connectivity before scanning
- **Live System Health** — Real-time CPU, memory, and network monitoring
- **Tool Integration** — Orchestrates nmap, ffuf, nikto, httpx, gau, waybackurls, assetfinder, nuclei, and more

## Stack

- Node.js (runs in Termux)
- Groq API — `llama-3.3-70b-versatile`
- Shell — tool orchestration via child_process
- ANSI/terminal rendering — no frontend framework

## Usage

```bash
# Install dependencies
npm install

# Set your Groq API key
export GROQ_API_KEY=your_key_here

# Start a hunt
node hunt.js
# or
bash hunt.sh
```

## Architecture

```
0x-hunt/
├── hunt.js          # Main TUI + agentic loop
├── hunt.sh          # Shell launcher
├── server.js        # Optional web interface
├── public/          # Web frontend (server mode)
└── package.json
```

## Requirements

- Node.js 18+
- Termux (Android) or any Linux environment
- Groq API key — [get one free](https://console.groq.com)
- Optional: nmap, ffuf, nikto, httpx, gau, waybackurls, assetfinder, nuclei

## Disclaimer

This tool is intended for **authorized penetration testing and bug bounty hunting only**. Only use against targets you have explicit permission to test. The author is not responsible for misuse.

---

Built by [Archaeopteryx](https://github.com/Archaeopteryx0624) — from a phone, in Termux.
