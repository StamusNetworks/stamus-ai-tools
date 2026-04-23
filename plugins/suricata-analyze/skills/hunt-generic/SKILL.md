---
name: hunt-generic
description: Generic highlevel threat hunt in network traffic from PCAP files or Suricata EVE JSON logs
---

# Hunt: High-Priority Threat Hunting

Execute these hunting queries systematically and report findings.

**IMPORTANT**: When executing multiple hunts, combine them into a single Bash command to avoid multiple confirmation prompts. Use semicolons to chain commands and echo separators for clarity.

This skill provides structured threat hunting methodologies for detecting:
- Malware C2 (Command & Control) communications
- Data exfiltration attempts
- Suspicious user agents and connection patterns
- Domain generation algorithms (DGA)
- Malicious TLDs and hosting infrastructure
- Lateral movement and reconnaissance
- Protocol anomalies and evasion techniques

## Hunt 1: Critical/Major Alerts (If Rules Loaded)

**Objective**: Identify high-severity threats detected by signatures

```bash
# Get Critical and Major alerts
jq 'select(.event_type=="alert" and ((.alert.metadata.signature_severity // "") | test("Critical|Major")))' "$tmpfile" | jq -s 'group_by(.alert.signature) | map({signature: .[0].alert.signature, severity: .[0].alert.metadata.signature_severity, count: length, flow_ids: [.[].flow_id] | unique})'
```

**Look for:**
- Alerts related to malware, exploits, C2 traffic
- Multiple hits on the same signature
- Alerts targeting specific internal hosts

**Report format:**
- Signature name and severity
- Number of occurrences
- Affected hosts (src/dst IPs)
- Flow IDs for investigation

## Hunt 2: Suspicious HTTP User Agents to IP Addresses

**Objective**: Find direct HTTP connections to IP addresses (no domain) with suspicious user agents

```bash
# HTTP connections to IPs with user agent details
jq -r 'select(.event_type=="http" and .http.hostname and (.http.hostname | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) | {ip: .http.hostname, agent: .http.http_user_agent, src: .src_ip, dst: .dest_ip, flow_id: .flow_id, url: .http.url}' "$tmpfile" | jq -s 'group_by(.ip) | map({target_ip: .[0].ip, agents: [.[].agent] | unique, count: length, sources: [.[].src] | unique, sample_flow: .[0].flow_id})'
```

**Suspicious indicators:**
- Generic user agents: `curl`, `wget`, `python-requests`, `Go-http-client`
- Missing or minimal user agents
- Outdated browser versions
- Scripting language agents: `Python`, `PowerShell`, `ruby`

**Why this matters:**
- Malware often connects to IP addresses instead of domains
- Legitimate browsers rarely connect directly to IPs
- C2 infrastructure often uses IP-based callbacks

**Report format:**
- Target IP address
- User agent(s) used
- Source IPs making the connections
- Sample flow_id for detailed investigation

## Hunt 3: Suspicious TLDs (.xyz, .top, .cc, etc.)

**Objective**: Identify connections to high-risk top-level domains

```bash
# DNS queries to suspicious TLDs
jq -r 'select(.event_type=="dns" and .dns.query.rrname and (.dns.query.rrname | test("\\.(xyz|top|cc|tk|ml|ga|cf|gq|pw|loan|download|click|stream|science)$"))) | {domain: .dns.query.rrname, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile" | jq -s 'group_by(.domain) | map({domain: .[0].domain, sources: [.[].src_ip] | unique, count: length, sample_flow: .[0].flow_id})'

# HTTP/HTTPS connections to suspicious TLDs
jq -r 'select(.event_type=="http" and .http.hostname and (.http.hostname | test("\\.(xyz|top|cc|tk|ml|ga|cf|gq|pw|loan|download|click|stream|science)$"))) | {domain: .http.hostname, agent: .http.http_user_agent, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile" | jq -s 'group_by(.domain) | map({domain: .[0].domain, agents: [.[].agent] | unique, sources: [.[].src_ip] | unique, count: length, sample_flow: .[0].flow_id})'
```

**High-risk TLDs:**
- `.xyz`, `.top` - Commonly used for malware/phishing
- `.cc`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq` - Free domains, abuse-prone
- `.pw`, `.loan`, `.download`, `.click` - Associated with malicious campaigns

**Report format:**
- Domain name with suspicious TLD
- Source IPs querying/connecting
- User agents (for HTTP/HTTPS)
- Number of connections
- Sample flow_id

## Hunt 4: Data Exfiltration - Large Outbound Transfers

**Objective**: Detect potential data theft via large uploads

```bash
# Flows with large client-to-server transfers (>10MB)
jq 'select(.event_type=="flow" and .flow.bytes_toserver > 10000000) | {src_ip: .src_ip, dst_ip: .dest_ip, dst_port: .dest_port, bytes: .flow.bytes_toserver, duration: .flow.age, proto: .app_proto, flow_id: .flow_id}' "$tmpfile" | jq -s 'sort_by(.bytes) | reverse'
```

**Look for:**
- Large uploads to external IPs
- Uploads on uncommon ports
- Encrypted protocols (TLS) to unknown destinations
- Multiple small uploads to the same destination (beaconing with data)

**Report format:**
- Source IP (internal host)
- Destination IP and port
- Bytes transferred
- Duration of transfer
- Protocol used
- Flow_id

## Hunt 5: DNS Tunneling and DGA Detection

**Objective**: Identify DNS-based data exfiltration or domain generation algorithms

```bash
# Long DNS queries (potential tunneling)
jq -r 'select(.event_type=="dns" and .dns.query.rrname and (.dns.query.rrname | length) > 40) | {domain: .dns.query.rrname, length: (.dns.query.rrname | length), src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile" | jq -s 'sort_by(.length) | reverse | .[0:20]'

# High entropy domains (potential DGA)
jq -r 'select(.event_type=="dns" and .dns.query.rrname) | {domain: .dns.query.rrname, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile" | jq -s 'map(select(.domain | test("[bcdfghjklmnpqrstvwxyz]{8,}"))) | .[0:20]'
```

**DGA indicators:**
- Long random-looking domain names
- High ratio of consonants to vowels
- Unusual character patterns
- Numeric sequences in domains
- Queries with no successful resolution

**Report format:**
- Suspicious domain name
- Length or entropy indicator
- Source IP making queries
- Sample flow_id

## Hunt 6: Rare/Uncommon Protocols

**Objective**: Identify unusual protocols that may indicate lateral movement or tunneling

```bash
# Protocol distribution with rare ones highlighted
jq -r 'select(.event_type=="flow") | .app_proto // "unknown"' "$tmpfile" | sort | uniq -c | sort -n

# Connections using uncommon ports
jq 'select(.event_type=="flow" and .dest_port and (.dest_port > 1024 and .dest_port < 49152) and .app_proto != "tls" and .app_proto != "http") | {src_ip: .src_ip, dst_ip: .dest_ip, port: .dest_port, proto: .app_proto, flow_id: .flow_id}' "$tmpfile" | jq -s 'group_by(.port) | map({port: .[0].port, proto: .[0].proto, count: length, sources: [.[].src_ip] | unique})'
```

**Suspicious patterns:**
- SMB/RDP outside expected internal ranges
- SSH from workstations
- Database protocols (MySQL, PostgreSQL) from unexpected hosts
- Custom/unknown protocols

**Report format:**
- Protocol or port number
- Source and destination IPs
- Frequency
- Sample flow_id

## Hunt 7: Beaconing Detection

**Objective**: Identify C2 beaconing via periodic connections

```bash
# Repeated connections to same destination (potential beaconing)
jq -r 'select(.event_type=="flow") | "\(.src_ip) \(.dest_ip):\(.dest_port)"' "$tmpfile" | sort | uniq -c | sort -rn | head -20
```

**Beaconing indicators:**
- Same src → dst:port combinations repeated 10+ times
- Regular time intervals between connections
- Small data transfers (check and response)
- Connections to uncommon ports

**Follow-up analysis:**
```bash
# Examine flows between specific hosts
jq 'select(.event_type=="flow" and .src_ip=="<SRC>" and .dest_ip=="<DST>") | {timestamp: .timestamp, bytes_to: .flow.bytes_toserver, bytes_from: .flow.bytes_toclient, duration: .flow.age}' "$tmpfile"
```

**Report format:**
- Source IP (potentially compromised)
- Destination IP and port
- Number of connections
- Pattern analysis (regular intervals, similar sizes)

## Hunt 8: TLS/SSL Anomalies

**Objective**: Identify suspicious encrypted connections

```bash
# Self-signed or unusual certificates
jq 'select(.event_type=="tls" and .tls.issuerdn and (.tls.issuerdn | test("Self-signed|Unknown|localhost"))) | {sni: .tls.sni, issuer: .tls.issuerdn, subject: .tls.subject, src_ip: .src_ip, dst_ip: .dest_ip, flow_id: .flow_id}' "$tmpfile"

# TLS to IP addresses (no SNI or IP-based SNI)
jq 'select(.event_type=="tls" and ((.tls.sni // "" | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) or (.tls.sni == null))) | {dst_ip: .dest_ip, src_ip: .src_ip, issuer: .tls.issuerdn, flow_id: .flow_id}' "$tmpfile"

# Unusual JA3 fingerprints (if available)
jq -r 'select(.event_type=="tls" and .tls.ja3.hash) | .tls.ja3.hash' "$tmpfile" | sort | uniq -c | sort -n | head -10
```

**Suspicious indicators:**
- Self-signed certificates in external connections
- TLS connections to IP addresses
- Certificates with suspicious subjects/issuers
- Rare JA3 fingerprints (non-standard TLS clients)

**Report format:**
- SNI/destination
- Certificate details
- Source IP
- Anomaly type
- Flow_id

## Hunt 9: Internal Reconnaissance

**Objective**: Detect scanning and internal reconnaissance

```bash
# Hosts connecting to many destinations (potential scanning)
jq -r 'select(.event_type=="flow") | "\(.src_ip) \(.dest_ip):\(.dest_port)"' "$tmpfile" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Failed connection attempts (if available in flow.state)
jq 'select(.event_type=="flow" and .flow.state and (.flow.state | test("closed|timeout|reset"))) | {src_ip: .src_ip, dst_ip: .dest_ip, port: .dest_port, state: .flow.state}' "$tmpfile" | jq -s 'group_by(.src_ip) | map({source: .[0].src_ip, failed_conns: length, targets: [.[].dst_ip] | unique | length})'
```

**Scanning indicators:**
- Single host connecting to many destinations
- High ratio of failed connections
- Connections to multiple sequential ports
- SMB/RDP scanning within the network

**Report format:**
- Source IP (potential scanner)
- Number of unique destinations
- Ports targeted
- Success/failure ratio

## Hunt 10: HTTP Method Anomalies

**Objective**: Identify suspicious HTTP methods and paths

```bash
# Unusual HTTP methods
jq -r 'select(.event_type=="http" and .http.http_method and (.http.http_method | test("PUT|DELETE|CONNECT|TRACE|OPTIONS"))) | {method: .http.http_method, url: .http.url, hostname: .http.hostname, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile"

# Access to admin/config paths
jq -r 'select(.event_type=="http" and .http.url and (.http.url | test("admin|config|phpmyadmin|login|wp-admin|console|manager"))) | {url: .http.url, hostname: .http.hostname, method: .http.http_method, status: .http.status, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile"

# SQL injection or path traversal patterns
jq -r 'select(.event_type=="http" and .http.url and (.http.url | test("(union|select|\\.\\.|\\/\\/|exec|script)"))) | {url: .http.url, hostname: .http.hostname, src_ip: .src_ip, flow_id: .flow_id}' "$tmpfile"
```

**Report format:**
- HTTP method and URL
- Target hostname
- Source IP
- Response status (if available)
- Flow_id

# Phase 3: Report Generation

After executing relevant hunts, compile findings into a structured report:

## Threat Hunting Report Template

```
# Network Threat Hunting Report

**Analysis Period:** [timestamp range from data]
**Total Events Analyzed:** [event count]
**Data Source:** [PCAP filename or EVE log]

## Executive Summary
[Brief overview of key findings - compromised hosts, threat categories, severity]

## Critical Findings

# 1. [Threat Category - e.g., "Malware C2 Communication"]
**Severity:** Critical/Major
**Affected Hosts:** [list of internal IPs]
**Description:** [What was detected]
**Evidence:**
- Flow IDs: [list]
- Indicators: [IPs, domains, user agents]
**Recommendation:** [Immediate actions needed]

[Repeat for each critical finding]

## Detailed Hunting Results

# High-Severity Alerts (Hunt 1)
[If alerts found, detail them]
- No alerts detected / [Number] alerts detected
- [Details with flow_ids]

# Suspicious HTTP to IP Addresses (Hunt 2)
[Report findings]
- Hosts under attack: [internal IPs making connections]
- Suspicious destinations: [external IPs]
- User agents: [list]
- Flow IDs: [list for investigation]

# Suspicious TLD Connections (Hunt 3)
[Report findings]
- Domains contacted: [list]
- Affected hosts: [internal IPs]
- Flow IDs: [list]

# Data Exfiltration Candidates (Hunt 4)
[Report findings]
- Large transfers detected: [Yes/No]
- [Details if found]

# DNS Anomalies (Hunt 5)
[Report findings]

# Beaconing Activity (Hunt 7)
[Report findings]

[Continue for all executed hunts]

## Network Baseline
- Protocol distribution: [HTTP: X%, TLS: Y%, DNS: Z%]
- Top talkers: [Most active internal IPs]
- External connections: [Number of unique external IPs]

## Recommendations

**Immediate Actions:**
1. [Isolate compromised hosts]
2. [Block malicious IPs/domains]
3. [Investigate specific flow_ids]

**Follow-up Investigation:**
1. [Deep dive into specific flows]
2. [Check endpoint logs]
3. [Review firewall rules]

**Hunting Queries Used:**
[List the hunt queries executed for reproducibility]
```


