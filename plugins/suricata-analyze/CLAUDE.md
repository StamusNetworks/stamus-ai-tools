# Suricata Analyze Plugin Instructions

This plugin provides a unified skill for inspecting network traffic using Suricata tools, supporting both PCAP file analysis and EVE JSON log analysis in a single workflow.

## When to Use This Plugin

Automatically invoke the `suricata-analyze:inspect` skill when users:

### Network Traffic Analysis Requests
- User provides a PCAP file and wants to analyze it
- User provides an EVE JSON log file and wants to investigate it
- User asks to extract network traffic data from a packet capture
- User wants to understand what's in a PCAP file or log file
- User asks to test Suricata rules against captured traffic
- User mentions analyzing network packets, packet captures, or Suricata logs
- User wants to see protocol distribution in traffic
- User asks about using `suricata-read` command
- User wants to investigate alerts or security events
- User asks about alert triage or incident investigation
- User wants to filter or search EVE logs

### Examples

**PCAP Analysis:**
- "Analyze this PCAP file: traffic.pcap"
- "What network traffic is in this packet capture?"
- "Run suricata-read on my-capture.pcap"
- "Extract HTTP traffic from this PCAP"
- "Test my Suricata rules against sample.pcap"
- "Convert this PCAP to JSON format"
- "What protocols are in this packet capture?"

**EVE Log Analysis:**
- "Analyze this eve.json file"
- "What alerts are in my Suricata logs?"
- "Investigate the security events in eve.json"
- "Show me all HTTP traffic in the logs"
- "What are the top alerts in this log file?"
- "Find all connections to IP 192.168.1.100"
- "Analyze DNS queries in the EVE log"
- "Help me investigate this incident using eve.json"

**General Network Analysis:**
- "Analyze this network traffic file"
- "What's in this capture?"
- "Investigate suspicious activity in [file]"

## Key Concepts

### Unified Workflow

The skill handles both input types seamlessly:
1. **PCAP files** (.pcap, .pcapng) are processed with `suricata-read` to generate EVE JSON
2. **EVE JSON logs** (.json, eve.json) are analyzed directly
3. Both ultimately work with EVE JSON format for analysis

The skill automatically determines which approach to use based on the file type.

### PCAP Files
- Packet capture files containing raw network traffic
- Processed using `suricata-read` command
- Outputs EVE JSON-formatted network events
- Can include optional rules file for detection testing

### EVE JSON Logs
- Suricata's native JSON event log format (Extensible Event Format)
- One JSON object per line (JSONL/NDJSON format)
- Contains alerts, flows, protocol metadata, and more
- Analyzed using standard JSON tools (jq, grep, etc.)

### Event Types
The skill works with various Suricata event types:
- **alert**: Security alerts and rule matches
- **flow**: Network connection metadata
- **http**, **tls**, **dns**, **ssh**, **smb**: Application layer protocols
- **fileinfo**: Extracted file metadata
- **anomaly**: Protocol violations and anomalies

## How the Skill Works

The skill follows this decision tree:

1. **Identify input type**:
   - File extension `.pcap`, `.pcapng` → Process with `suricata-read` first
   - File extension `.json` or filename contains `eve` → Analyze directly
   - If unclear, ask the user

2. **Process if needed**:
   - PCAP: Run `suricata-read` (with `--container` if Suricata not installed locally)
   - Optional: Include `--rules-file` if user wants detection testing
   - Output EVE JSON to a file or pipe for analysis

3. **Analyze EVE JSON**:
   - Parse events by type
   - Extract relevant information based on user's question
   - Present findings with context and recommendations

## Integration with Other Plugins

This plugin complements the `suricata-rules` plugin:
- Use `suricata-rules:writer` to create detection rules
- Use `suricata-analyze:inspect` to test those rules against sample traffic (PCAP)
- Use `suricata-analyze:inspect` to investigate the alerts generated (EVE logs)

## Common Workflows

### Workflow 1: Rule Development and Testing
1. User writes rules with `suricata-rules:writer`
2. User tests rules: `suricata-analyze:inspect` processes PCAP with rules file
3. User analyzes the results (alerts) from the EVE JSON output

### Workflow 2: Incident Investigation
1. User provides eve.json from a Suricata sensor
2. Use `suricata-analyze:inspect` to investigate alerts and events
3. Identify suspicious activity and provide recommendations

### Workflow 3: Traffic Baseline Analysis
1. User provides a PCAP file of unknown traffic
2. Use `suricata-analyze:inspect` to extract protocol information
3. Summarize findings: protocol distribution, top talkers, services

### Workflow 4: Threat Hunting
1. User provides EVE logs or PCAP from a suspect system
2. Use `suricata-analyze:inspect` to hunt for indicators
3. Examine DNS queries, TLS certificates, large transfers, suspicious patterns
4. Report findings with evidence

## Proactive Behavior

When users mention:
- PCAP files, packet captures, or network traffic files → Invoke `suricata-analyze:inspect`
- EVE logs, eve.json, Suricata logs, or JSON logs → Invoke `suricata-analyze:inspect`
- Network traffic analysis → Invoke `suricata-analyze:inspect`
- Suricata alerts or events → Invoke `suricata-analyze:inspect`
- Testing rules against traffic → Invoke `suricata-analyze:inspect`
- Protocol analysis, traffic investigation → Invoke `suricata-analyze:inspect`

Always prefer using this specialized skill over attempting to analyze network traffic or logs without it, as it contains essential domain knowledge, best practices, and structured analysis approaches for both PCAP and EVE JSON formats.
