# Suricata Analyze Plugin Instructions

This plugin provides specialized skills for analyzing network traffic using Suricata tools, supporting PCAP file analysis, EVE JSON log analysis, and threat hunting.

## Available Skills

### 1. `suricata-analyze:inspect` - General Traffic Analysis
### 2. `suricata-analyze:hunt` - Threat Hunting

## When to Use Each Skill

### Use `suricata-analyze:inspect` when users want general analysis:

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

### Use `suricata-analyze:hunt` when users want threat hunting:

**Threat Hunting Requests:**
- User asks to hunt for threats or malicious activity
- User wants to find C2 (Command & Control) traffic
- User asks about data exfiltration or suspicious uploads
- User mentions looking for compromised hosts
- User wants to detect beaconing or malware communication
- User asks to find suspicious user agents or domains
- User requests hunting for specific threat patterns
- User wants a security assessment of traffic

**Examples:**
- "Hunt for threats in this PCAP"
- "Look for malicious activity in traffic.pcap"
- "Find any C2 communication in eve.json"
- "Hunt for compromised hosts in this capture"
- "Look for data exfiltration attempts"
- "Find suspicious user agents and domains"
- "Hunt for beaconing activity"
- "Are there any infected hosts in this traffic?"
- "Look for malware communication patterns"
- "Perform threat hunting on sample.pcap"

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

2. **Proactively check for Suricata rules** (for PCAP files):
   - **IMPORTANT**: Always search for `.rules` files in the current directory and subdirectories
   - Present any found rules files to the user and ask if they want to load them
   - If no rules found, still ask if the user has rules they want to use
   - Explain the benefit: loading rules enables threat detection and alert generation

3. **Process if needed**:
   - PCAP: Run `suricata-read` (with `--container` if Suricata not installed locally)
   - Include `--rules-file` parameter if user wants detection (based on step 2)
   - Output EVE JSON to a file or pipe for analysis

4. **Analyze EVE JSON**:
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
1. User provides EVE logs or PCAP and wants to hunt for threats
2. Use `suricata-analyze:hunt` for systematic threat hunting
3. Execute 10+ hunting queries covering C2, exfiltration, suspicious domains, etc.
4. Generate comprehensive threat hunting report with findings and recommendations

### Workflow 5: Combined Analysis and Hunting
1. User provides traffic and wants both analysis and hunting
2. First use `suricata-analyze:inspect` to understand the traffic baseline
3. Then use `suricata-analyze:hunt` to find threats
4. Cross-reference findings from both approaches

## Proactive Behavior

### For General Analysis:
When users mention:
- PCAP files, packet captures, or network traffic files (general) → `suricata-analyze:inspect`
- EVE logs, eve.json, Suricata logs (general) → `suricata-analyze:inspect`
- Protocol distribution, traffic baseline → `suricata-analyze:inspect`
- Suricata alerts or events (investigation) → `suricata-analyze:inspect`
- Testing rules against traffic → `suricata-analyze:inspect`

### For Threat Hunting:
When users mention:
- Hunting, finding threats, malicious activity → `suricata-analyze:hunt`
- C2, command and control, beaconing → `suricata-analyze:hunt`
- Data exfiltration, suspicious uploads → `suricata-analyze:hunt`
- Compromised hosts, infected machines → `suricata-analyze:hunt`
- Suspicious user agents, domains, TLDs → `suricata-analyze:hunt`
- Security assessment, threat detection → `suricata-analyze:hunt`

### Skill Differences:

**`inspect`**: General-purpose analysis
- Protocol distribution
- Alert investigation
- Flow statistics
- Ad-hoc queries

**`hunt`**: Structured threat hunting
- 10 systematic hunting queries
- Threat-focused (C2, exfiltration, DGA, etc.)
- Comprehensive report generation
- Security-specific indicators

Always prefer using these specialized skills over attempting to analyze network traffic or logs without them, as they contain essential domain knowledge, best practices, and structured analysis approaches.
