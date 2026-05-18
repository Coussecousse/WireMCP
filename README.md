![Wire-MCP Banner](Wire-MCP.png)


# WireMCP
WireMCP is a Model Context Protocol (MCP) server designed to empower Large Language Models (LLMs) with real-time network traffic analysis capabilities. By leveraging tools built on top of Wireshark's `tshark`, WireMCP captures and processes live network data, providing LLMs with structured context to assist in tasks like threat hunting, network diagnostics, and anomaly detection.

# Features
WireMCP exposes the following tools to MCP clients, enhancing LLM understanding of network activity:

- **`capture_packets`**: Captures live traffic and returns raw packet data as JSON, enabling LLMs to analyze packet-level details (e.g., IP addresses, ports, HTTP methods).
- **`get_summary_stats`**: Provides protocol hierarchy statistics, giving LLMs an overview of traffic composition (e.g., TCP vs. UDP usage).
- **`get_conversations`**: Delivers TCP/UDP conversation statistics, allowing LLMs to track communication flows between endpoints.
- **`check_threats`**: Captures IPs and checks them against the URLhaus blacklist, equipping LLMs with threat intelligence context for identifying malicious activity.
- **`check_ip_threats`**: Performs targeted threat intelligence lookups for specific IP addresses against multiple threat feeds, providing detailed reputation and threat data.
- **`analyze_pcap`**: Analyzes PCAP files to provide comprehensive packet data in JSON format, enabling detailed post-capture analysis of network traffic.
- **`extract_credentials`**: Scans PCAP files for potential credentials from various protocols (HTTP Basic Auth, FTP, Telnet), aiding in security audits and forensic analysis.
- **`extract_icmp_data`**: Extracts and decodes ICMP payload data with hex dump fallback for sub-dissector masked packets, enabling detection of hidden messages or covert channels via ICMP.


## New Tools (PCAP Forensics)

In addition to the base features, WireMCP includes **8 advanced forensic tools** for deep PCAP analysis plus an **automated report generator**:

- **`follow_tcp_stream`**: Reconstructs TCP conversations in ASCII, hex, or raw mode — essential for reading C2 commands, exfiltrated data, and protocol payloads.
- **`get_expert_info`**: Extracts Wireshark expert info (errors, warnings, notes) to quickly identify malformed packets, protocol anomalies, and suspicious behavior.
- **`extract_http_objects`**: Extracts HTTP objects (scripts, images, documents) transferred over HTTP with SHA256 hashes — useful for identifying malware downloads.
- **`get_pcap_statistics`**: Provides protocol hierarchy and packet length statistics for traffic profiling.
- **`get_conversation_timeline`**: Generates time-windowed conversation summaries for incident reconstruction and beaconing detection.
- **`search_payloads`**: Searches packet payloads for ASCII strings (converted to hex internally for tshark compatibility) — ideal for finding C2 patterns, credentials, or IOCs.
- **`extract_tls_metadata`**: Extracts TLS handshake metadata (SNI, TLS versions) for identifying encrypted C2 channels.
- **`get_endpoint_stats`**: Lists all unique IP endpoints with packet counts, traffic direction, and protocol breakdown.
- **`generate_incident_report`**: **NEW** — Runs all analyses automatically and generates a comprehensive structured incident report with:
  - Executive summary
  - Network topology & key hosts
  - Indicators of Compromise (IOCs)
  - **Wireshark verification steps** (display filters and procedures to reproduce each finding in Wireshark GUI)
  - Traffic timeline
  - Remediation recommendations

### Report Structure

Each incident report follows this template:

```markdown
# Incident Report — <pcap_filename>

## 1. Executive Summary
File info, traffic overview, key findings summary

## 2. Network Topology & Key Hosts
Top talkers table (IP, packet counts, protocols)

## 3. Indicators of Compromise (IOCs)
- TLS connections (SNI, versions)
- Suspicious payload patterns
- HTTP objects with SHA256 hashes
- Protocol anomalies (expert info)

## 4. Wireshark Verification Steps
For each finding: display filter + step-by-step GUI procedure
- Verify top talkers: `ip.addr == <IP>`
- Verify TLS: `tls.handshake.type == 1`
- Verify payloads: `frame contains "<pattern>"`
- Export HTTP objects: `File > Export Objects > HTTP...`
- General 10-step investigation workflow

## 5. Traffic Timeline

## 6. Remediation Steps
```

## How It Helps LLMs
WireMCP bridges the gap between raw network data and LLM comprehension by:
- **Contextualizing Traffic**: Converts live packet captures into structured outputs (JSON, stats) that LLMs can parse and reason about.
- **Threat Detection**: Integrates IOCs (currently URLhaus) to flag suspicious IPs, enhancing LLM-driven security analysis.
- **Diagnostics**: Offers detailed traffic insights, enabling LLMs to assist with troubleshooting or identifying anomalies.
- **Narrative Generation**: LLM's can Transform complex packet captures into coherent stories, making network analysis accessible to non-technical users.

# Installation

## Prerequisites
- Mac / Windows / Linux
- [Wireshark](https://www.wireshark.org/download.html) (with `tshark` installed and accessible in PATH)
- Node.js (v16+ recommended)
- npm (for dependency installation)

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/0xkoda/WireMCP.git
   cd WireMCP
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the MCP server:
   ```bash
   node index.js
   ```

> **Note**: Ensure `tshark` is in your PATH. WireMCP will auto-detect it or fall back to common install locations (e.g., `/Applications/Wireshark.app/Contents/MacOS/tshark` on macOS).

# Usage with MCP Clients

WireMCP works with any MCP-compliant client. Below are examples for popular clients:

## Example 1: Cursor

Edit `mcp.json` in Cursor -> Settings -> MCP :

```json
{
  "mcpServers": {
    "wiremcp": {
      "command": "node",
      "args": [
        "/ABSOLUTE_PATH_TO/WireMCP/index.js"
      ]
    }
  }
}
```

**Location (macOS)**: `/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json`

## Example 2: Opencode

Add to your `opencode.json` configuration (usually at `~/.config/opencode/opencode.json` or project root):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "wiremcp": {
      "type": "local",
      "command": [
        "node",
        "/ABSOLUTE_PATH_TO/WireMCP/index.js"
      ],
      "enabled": true
    }
  }
}
```

> **Note**: Replace `/ABSOLUTE_PATH_TO/WireMCP/index.js` with the actual absolute path on your system (e.g., `/home/kali/Documents/pentests/WireMCP/index.js`).

Then restart opencode. The WireMCP tools will be available for PCAP analysis during your sessions.

## Other Clients

This MCP will work well with any client. Use the command `node /path/to/WireMCP/index.js` in their MCP server settings.

# Example Output

Running `check_threats` might yield:

```
Captured IPs:
174.67.0.227
52.196.136.253

Threat check against URLhaus blacklist:
No threats detected in URLhaus blacklist.
```

Running `analyze_pcap` on a capture file:

```json
{
  "content": [{
    "type": "text",
    "text": "Analyzed PCAP: ./capture.pcap\n\nUnique IPs:\n192.168.0.2\n192.168.0.1\n\nProtocols:\neth:ethertype:ip:tcp\neth:ethertype:ip:tcp:telnet\n\nPacket Data:\n[{\"layers\":{\"frame.number\":[\"1\"],\"ip.src\":[\"192.168.0.2\"],\"ip.dst\":[\"192.168.0.1\"],\"tcp.srcport\":[\"1550\"],\"tcp.dstport\":[\"23\"]}}]"
  }]
}
```


LLMs can use these outputs to:
- Provide natural language explanations of network activity
- Identify patterns and potential security concerns
- Offer context-aware recommendations
- Generate human-readable reports

# Roadmap

- **Expand IOC Providers**: Currently uses URLhaus for threat checks. Future updates will integrate additional sources (e.g., IPsum, Emerging Threats) for broader coverage.


# Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

# License

[MIT](LICENSE)

# Acknowledgments

- Wireshark/tshark team for their excellent packet analysis tools
- Model Context Protocol community for the framework and specifications
- URLhaus for providing threat intelligence data