# Wazuh Decoder & Rule Auto-Generator

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Instantly generate syntactically perfect Wazuh `<decoder>` and `<rule>` XML configurations from raw, unstructured log lines. 

Stop wasting hours manually writing complex PCRE2 regular expressions. This tool uses a Deterministic Python Heuristic Engine to instantly analyze your logs, bridge static text, and guarantee 100% mathematically valid Wazuh output.

## Features
- **Bulk Log Analysis (Killer Feature):** Paste 1,000 logs at once. The engine identifies the top 3 most common structural patterns and lets you generate decoders for them with one click.
- **Instant In-App Simulation:** Generate the XML and instantly see a simulation of exactly what Wazuh will extract. No need to touch a terminal.
- **100% Local & Private:** Runs entirely via Docker. No data ever leaves your network.
- **Anchor & Bridge Architecture:** Uses PCRE2 `.*?` non-greedy bridging to effortlessly navigate complex punctuation, brackets, and proprietary log formats without breaking.
- **Native Wazuh Compatibility:** Automatically maps extracted fields to native Wazuh variables (`user`, `srcip`, `dstip`) and uses `<regex type="pcre2">` for maximum compatibility.
- **Zero Hallucinations:** Pure Python heuristics. No LLMs, no waiting, no API costs.

## Tested Against
- Empty/missing field values
- ReDoS-resistant (no hanging on massive payloads)
- Special characters (apostrophes, hyphens, semicolons)
- Proprietary/unstructured formats (not just CEF/LEEF)
- Graceful fallback for unparseable logs

## Why This Over Browser Tools?
- Backend Python engine (handles bulk processing)
- API-ready for MSSP automation
- Docker deployment (no browser limits)

## Quick Start

### Prerequisites
- Docker & Docker Compose installed on your machine.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/wazuh-auto-generator.git
   cd wazuh-auto-generator
   ```
2. Start the application:
   ```bash
   docker compose up -d
   ```
3. Open your browser and navigate to: **http://localhost:8000**

## How It Works
1. **Input:** Paste a single raw log line, or use the Bulk Processing tab to analyze hundreds of logs at once.
2. **Heuristic Analysis:** The Python engine identifies the anchor, extracts dynamic fields (IPs, KV pairs, Quoted Strings), and bridges the static text.
3. **Simulation:** The app instantly simulates the extraction and shows you the exact fields Wazuh will parse.
4. **Output:** You receive ready-to-paste `<decoder>` and `<rule>` XML blocks.

## Testing in Your Wazuh Environment
To verify the generated rules without deploying an agent:
1. Copy the generated XML into `/var/ossec/etc/decoders/local_decoder.xml` and `/var/ossec/etc/rules/local_rules.xml`.
2. Restart the manager: `systemctl restart wazuh-manager`
3. Test the log using Wazuh's built-in tool:
   ```bash
   /var/ossec/bin/wazuh-logtest
   ```
   Paste your log. You should see `Rule matched` and your fields correctly extracted in Phase 3.

## Tech Stack
- **Backend:** Python, FastAPI, Uvicorn
- **Engine:** Pure Python `re` (PCRE2 compatible)
- **Frontend:** Vanilla HTML/JS, Jinja2 Templating