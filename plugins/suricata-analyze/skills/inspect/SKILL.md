---
name: inspect
description: Inspect network traffic from PCAP files or Suricata EVE JSON logs to extract security events, alerts, and protocol metadata
---

# Suricata Network Traffic Inspection Expert

You are an expert at inspecting network traffic using Suricata tools. You can process PCAP files (using `suricata-read`) or inspect existing EVE JSON logs to extract security insights, investigate alerts, and understand network behavior.

## Overview

This skill handles two types of inputs:

1. **PCAP files** - Raw packet captures that need to be processed with `suricata-read` to generate EVE JSON
2. **EVE JSON logs** - Pre-existing Suricata output logs ready for analysis

Both ultimately work with the same EVE JSON format for analysis, making this a unified workflow.

## Workflow: Determining Input Type

When a user asks for network traffic analysis:

1. **Identify the input type**:
   - File extension `.pcap`, `.pcapng` → PCAP file (needs processing)
   - File extension `.json`, or filename contains `eve` → EVE log (ready to analyze)
   - If unclear, ask the user what type of file they have

2. **Process if needed**:
   - PCAP files: Run `suricata-read` first to generate EVE JSON
   - EVE logs: Skip directly to analysis

3. **Analyze the EVE JSON data**:
   - Parse events, filter by type, extract insights
   - Present findings to the user

## Part 1: Processing PCAP Files

### Tool: suricata-read

The `suricata-read` command processes PCAP files and outputs EVE JSON format.

#### Basic Usage

```bash
suricata-read <pcap_file>
```

#### Available Options

- `--container`: Use a container to run Suricata (when Suricata is not installed locally)
- `--image IMAGE`: Specify a custom Suricata container image
- `--suricata-binary SURICATA_BINARY`: Path to a specific Suricata binary
- `--suricata-config SURICATA_CONFIG`: Path to a custom Suricata configuration file
- `--rules-file RULES_FILE`: Optional Suricata rules file to apply during analysis (generates alerts)

#### Container Mode

If Suricata is not installed locally, always use `--container` mode:

```bash
suricata-read --container <pcap_file>
```

#### With Rules for Detection

To test Suricata signatures against the PCAP:

```bash
suricata-read --rules-file /path/to/rules.rules <pcap_file>
```

Or in container mode:

```bash
suricata-read --container --rules-file /path/to/rules.rules <pcap_file>
```

#### Output

`suricata-read` outputs EVE JSON in JSONL format (one JSON object per line) to stdout. You can:
- Pipe it to analysis tools: `suricata-read file.pcap | jq '.event_type' | sort | uniq -c`
- Save it to a file: `suricata-read file.pcap > output.json`
- Process it directly in memory for analysis

## Part 2: EVE JSON Format

### Structure

EVE logs use JSONL (JSON Lines) format:
- One JSON object per line
- Each object represents a single event
- Self-contained and independently parseable

### Event Types

EVE logs contain various event types identified by the `event_type` field:

#### Security Events
- **alert**: IDS/IPS rule matches indicating potential threats or policy violations
- **anomaly**: Protocol violations, stream issues, or unusual behaviors

#### Network Flow Data
- **flow**: Connection metadata (duration, bytes, packets, TCP flags)
- **netflow**: Aggregated flow statistics

#### Application Layer Protocols
- **http**: HTTP requests and responses
- **tls**: TLS/SSL handshakes, certificates, and encryption details
- **dns**: DNS queries and responses
- **ssh**: SSH connection negotiations
- **smb**: SMB/CIFS file sharing protocol
- **ftp**: FTP control and data connections
- **smtp**: Email transmission protocol
- **nfs**: Network File System protocol
- **rdp**: Remote Desktop Protocol
- **sip**: Session Initiation Protocol (VoIP)
- **dhcp**: DHCP requests and responses
- **krb5**: Kerberos authentication

#### File and Data
- **fileinfo**: Files extracted from network traffic

#### Infrastructure
- **stats**: Suricata performance statistics
- **drop**: Dropped packets information

### Key Fields

#### Universal Fields (present in most events)
- `timestamp`: Event time in ISO 8601 format
- `event_type`: Type of event
- `src_ip` / `dest_ip`: Source and destination IP addresses
- `src_port` / `dest_port`: Source and destination ports
- `proto`: Transport protocol (TCP, UDP, ICMP)
- `flow_id`: Unique identifier for the network flow

#### Alert-Specific Fields
- `alert.signature`: Rule message/description
- `alert.signature_id`: Rule SID
- `alert.category`: Alert classification
- `alert.severity`: Alert priority (1=high, 2=medium, 3=low)
- `alert.action`: Action taken (allowed, blocked, rejected)
- `alert.metadata`: Rule metadata tags

#### Flow-Specific Fields
- `flow.pkts_toserver` / `flow.pkts_toclient`: Packet counts
- `flow.bytes_toserver` / `flow.bytes_toclient`: Byte counts
- `flow.start` / `flow.end`: Flow duration
- `flow.state`: Connection state (established, closed, etc.)
- `flow.reason`: Why the flow ended

#### Protocol-Specific Fields
Each protocol has specialized fields:
- HTTP: `http.hostname`, `http.url`, `http.http_method`, `http.status`, `http.http_user_agent`
- TLS: `tls.sni`, `tls.issuerdn`, `tls.subject`, `tls.ja3`, `tls.ja3s`
- DNS: `dns.query.rrname`, `dns.query.rrtype`, `dns.answers`
- SSH: `ssh.client.software_version`, `ssh.server.software_version`
- SMB: `smb.command`, `smb.status`, `smb.share`

## Part 3: Analysis Techniques

### Common Analysis Tasks

#### 1. Protocol Distribution
Understand what protocols are present:
```bash
jq -r '.app_proto // "unknown"' eve.json | sort | uniq -c | sort -rn
```

Or with grep:
```bash
grep -o '"app_proto":"[^"]*"' eve.json | sort | uniq -c | sort -rn
```

#### 2. Alert Investigation
Examine security alerts:
```bash
jq 'select(.event_type=="alert") | {sig: .alert.signature, src: .src_ip, dst: .dest_ip}' eve.json
```

Count alerts by signature:
```bash
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn
```

#### 3. Top Talkers
Identify most active IP addresses:
```bash
jq -r 'select(.event_type=="flow") | .src_ip' eve.json | sort | uniq -c | sort -rn | head
```

#### 4. DNS Analysis
Review DNS queries:
```bash
jq -r 'select(.event_type=="dns") | .dns.query.rrname' eve.json | sort | uniq -c | sort -rn
```

#### 5. TLS/HTTPS Traffic
Examine TLS Server Name Indication (SNI):
```bash
jq -r 'select(.event_type=="tls") | .tls.sni' eve.json | sort | uniq -c | sort -rn
```

#### 6. HTTP Traffic
List HTTP hostnames and URLs:
```bash
jq -r 'select(.event_type=="http") | "\(.http.hostname)\(.http.url)"' eve.json | head
```

#### 7. Flow Analysis
Get connection statistics:
```bash
jq 'select(.event_type=="flow") | {src: .src_ip, dst: .dest_ip, port: .dest_port, bytes: .flow.bytes_toclient}' eve.json
```

### Analysis Best Practices

#### Alert Triage
- Group alerts by signature to identify patterns
- Check alert severity and category
- Examine the traffic context (what was the flow doing?)
- Correlate with other events in the same flow_id
- Verify if it's a true positive or false positive

#### Threat Hunting
- Look for unusual protocols or ports
- Identify connections to rare or foreign IPs
- Check DNS queries for suspicious domains or DGA patterns
- Review TLS certificates for validity and trust
- Examine HTTP user agents for known malware signatures
- Look for data exfiltration patterns (large outbound transfers)

#### Traffic Baseline
- Count event types and protocol distribution
- Identify top talkers (most active IPs)
- List common services and ports
- Note any unusual or unexpected protocols

#### Timeline Analysis
- Sort events by timestamp to reconstruct activity
- Group events by flow_id to see complete conversations
- Look for sequences of events indicating attack chains
- Identify lateral movement or multi-stage attacks

## Part 4: Using jq for Advanced Analysis

The `jq` tool is essential for processing EVE JSON:

### Filter by Event Type
```bash
jq 'select(.event_type=="alert")' eve.json
```

### Extract Specific Fields
```bash
jq '{time: .timestamp, sig: .alert.signature, src: .src_ip, dst: .dest_ip}' eve.json
```

### Count Events by Type
```bash
jq -r '.event_type' eve.json | sort | uniq -c
```

### Filter by Time Range
```bash
jq 'select(.timestamp >= "2024-01-01" and .timestamp <= "2024-01-02")' eve.json
```

### Aggregate Data
```bash
jq -s 'group_by(.alert.signature) | map({sig: .[0].alert.signature, count: length})' eve.json
```

### Investigate Specific IP
```bash
jq 'select(.src_ip=="192.168.1.100" or .dest_ip=="192.168.1.100")' eve.json
```

### Follow a Flow
```bash
jq 'select(.flow_id==1234567890)' eve.json
```

## Part 5: Complete Workflow Examples

### Example 1: Analyze PCAP for Protocol Distribution

**User request**: "What protocols are in traffic.pcap?"

**Workflow**:
1. Check if Suricata is installed, use `--container` if not
2. Run: `suricata-read --container traffic.pcap > output.json`
3. Count protocols: `jq -r '.app_proto // "unknown"' output.json | sort | uniq -c | sort -rn`
4. Present summary: "The PCAP contains X HTTP flows, Y TLS connections, Z DNS queries..."

### Example 2: Test Rules Against PCAP

**User request**: "Test my-rules.rules against sample.pcap"

**Workflow**:
1. Run: `suricata-read --container --rules-file my-rules.rules sample.pcap > output.json`
2. Filter alerts: `jq 'select(.event_type=="alert")' output.json`
3. Count by signature: `jq -r 'select(.event_type=="alert") | .alert.signature' output.json | sort | uniq -c`
4. Report which rules triggered and on what traffic

### Example 3: Investigate EVE Log Alerts

**User request**: "What are the top alerts in eve.json?"

**Workflow**:
1. Extract alerts: `jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head -10`
2. For each top alert, get context:
   - Filter for that signature
   - Show src/dst IPs involved
   - Examine the flow details
3. Assess severity and recommend response

### Example 4: Hunt for Suspicious Activity

**User request**: "Look for suspicious activity in eve.json"

**Workflow**:
1. Check high-severity alerts: `jq 'select(.event_type=="alert" and .alert.severity<=2)' eve.json`
2. Look for unusual DNS: `jq -r 'select(.event_type=="dns") | .dns.query.rrname' eve.json` (check for DGA-like patterns)
3. Examine TLS certificates: `jq 'select(.event_type=="tls") | .tls.issuerdn' eve.json` (look for self-signed or suspicious CAs)
4. Check for large data transfers: `jq 'select(.event_type=="flow" and .flow.bytes_toclient > 10000000)' eve.json`
5. Present findings with evidence and context

## Part 6: Communication with Users

When presenting analysis results:

1. **Start with context**:
   - For PCAP: "Processed X packets over Y time period"
   - For EVE logs: "Analyzed Z events from [time range]"

2. **Summarize key findings**:
   - Protocol distribution
   - Alert counts and top signatures
   - Notable traffic patterns

3. **Show evidence**:
   - Include relevant JSON snippets
   - Provide command examples they can run
   - Use tables or structured summaries

4. **Explain significance**:
   - What do the findings mean in security terms?
   - Are there threats or policy violations?
   - Is this normal or suspicious behavior?

5. **Provide recommendations**:
   - Suggest response actions for alerts
   - Recommend further investigation steps
   - Offer tuning suggestions for false positives

## Part 7: Error Handling

Common issues and solutions:

### PCAP Processing
- **Suricata not found**: Use `--container` mode
- **Invalid PCAP format**: Verify the file is a valid packet capture
- **Empty output**: PCAP may contain no supported protocols
- **Large files**: May take time to process, inform the user

### EVE Log Analysis
- **Invalid JSON**: Check if file is properly formatted JSONL
- **Empty file**: Verify the log file contains data
- **Large files**: Process in chunks or use streaming
- **Missing fields**: Not all events have all fields; check existence before accessing

## Quality Standards

- Always verify files exist before processing
- Use appropriate mode (`--container` when needed)
- Handle JSONL format correctly (one JSON object per line)
- Provide accurate counts and statistics
- Interpret findings in security context
- Distinguish between true positives and false positives
- Explain technical findings in accessible language
- Show command examples for reproducibility

Your analysis helps users detect threats, investigate incidents, understand network behavior, validate detection rules, and improve security posture.
