# Stamus AI Tools

A collection of AI-powered tools for network security professionals, featuring Suricata signature management and integration with Stamus Clear NDR platform.

## Overview

This repository provides skills and integrations designed to streamline network security operations, with a focus on Suricata
intrusion detection signatures and network defense and response workflows.

The skills can be used within AI agents to automate tasks such as signature analysis, creation, and validation. The repository
is structured to be a Claude Code plugin, making it easy to integrate into your existing AI workflows.


## Tools

### Suricata Rules Plugin for Claude Code

A comprehensive Claude Code plugin for working with Suricata network intrusion detection signatures.

**Skills:**

- **explain** - Get detailed explanations of Suricata signatures
  - Breaks down signature components (protocol, IPs, ports, content matching)
  - Explains the purpose and threat context
  - Clarifies traffic direction (inbound vs outbound)
  - Provides links to keyword documentation

- **writer** - Write and validate Suricata signatures following best practices
  - Generates signatures with proper syntax
  - Validates rules using `suricata-language-server`
  - Enforces best practices (no deprecated modifiers, proper metadata, etc.)
  - Includes automatic syntax checking and warnings

**Features:**

- Interactive signature creation with validation
- Detailed signature analysis and explanation
- Integration with `suricata-language-server` for syntax checking
- Best practices enforcement (metadata, thresholds, domain transforms)
- Support for both containerized and local Suricata installations

### Suricata Analyze Plugin for Claude Code

A powerful Claude Code plugin for analyzing network traffic using Suricata tools, with support for both PCAP files and EVE JSON logs. Includes general traffic analysis and specialized threat hunting.

**Skills:**

- **inspect** - Unified network traffic inspection for PCAP files and EVE JSON logs
  - Automatically detects input type (PCAP or EVE JSON)
  - Processes PCAP files using the `suricata-read` command to generate EVE JSON
  - Inspects EVE JSON logs directly for security events and traffic patterns
  - Supports protocol analysis (HTTP, TLS, DNS, SMB, SSH, etc.)
  - Optional rules file integration for detection testing with PCAPs
  - Alert triage and incident investigation
  - Container mode support for environments without local Suricata installation

- **hunt** - Systematic threat hunting in network traffic
  - 10+ structured hunting queries for detecting threats
  - C2 (Command & Control) communication detection
  - Data exfiltration identification (large uploads, suspicious transfers)
  - Suspicious user agents and direct IP connections
  - Malicious TLD detection (.xyz, .top, etc.)
  - DNS tunneling and DGA (Domain Generation Algorithm) identification
  - Beaconing detection for persistent malware
  - TLS/SSL anomalies and self-signed certificates
  - Internal reconnaissance and scanning detection
  - Comprehensive threat hunting report generation

**Features:**

- Unified workflow for PCAP and EVE log analysis
- Comprehensive PCAP processing with `suricata-read`
- EVE log parsing and security event investigation
- Protocol distribution and traffic pattern analysis
- Alert triage and incident response support
- Systematic threat hunting with 10+ detection methods
- Security-focused analysis (C2, exfiltration, malware indicators)
- jq-based filtering and aggregation examples
- Support for both containerized and local Suricata installations
- Secure temporary file handling with `mktemp`

## Installation

### Prerequisites

For the Suricata plugins, you'll need:

- Python 3.x
- `suricata-language-server` >= 2.0.0 (install via pip)

```bash
pip install suricata-language-server
```

If Suricata is not installed locally, you can use the containerized version with the `--container` flag for both plugins.

### Installing the Claude Code Plugin

#### From Claude Code Marketplace

You can add the plugins directly from the Claude Code marketplace:
```
/plugin marketplace add StamusNetworks/stamus-ai-tools
```
Then you can install the desired plugins:

```
/plugin install suricata-rules@stamus-ai-tools
/plugin install suricata-analyze@stamus-ai-tools
```

#### Manual Installation

1. Clone this repository
2. Install the desired plugins in Claude Code:

```bash
claude-code plugin install ./plugins/suricata-rules
claude-code plugin install ./plugins/suricata-analyze
```
### Installation for other AI agents

1. Clone this repository
2. Copy the directories containing the skills you want to use into your AI agent's plugin directory

For example, with OpenCode:

```bash
cp -r ./plugins/suricata-rules/* ~/.opencode/plugins/
cp -r ./plugins/suricata-analyze/* ~/.opencode/plugins/
```

## Usage

### Working with Suricata Signatures

#### Explaining Suricata Signatures

Use the `explain` skill to understand what a signature does. For example in Claude Code:

```
/suricata-rules:explain

[Paste your Suricata rule here]
```

The AI agent will provide a detailed breakdown of the signature's purpose, components, and threat context.

#### Writing Suricata Signatures

Use the `writer` skill to create new signatures. For example in Claude Code:

```
/suricata-rules:writer

I need a signature to detect DNS queries to malicious-domain.com
```

The AI agent will generate a properly formatted signature, validate it, and ensure it follows best practices.

### Inspecting Network Traffic

Use the `inspect` skill to work with both PCAP files and EVE JSON logs. For example in Claude Code:

**Inspecting PCAP Files:**

```
/suricata-analyze:inspect

Analyze traffic.pcap and show me the protocol distribution
```

The AI agent will process the PCAP file using `suricata-read`, extract network events in JSON format, and provide insights about the traffic.

**Inspecting EVE JSON Logs:**

```
/suricata-analyze:inspect

Investigate the alerts in eve.json and identify the top threats
```

The AI agent will parse the EVE log file, analyze security events, and provide a comprehensive investigation report.

**Testing Rules Against PCAPs:**

```
/suricata-analyze:inspect

Test my-rules.rules against sample.pcap
```

The AI agent will run `suricata-read` with the rules file, generate alerts, and report which signatures triggered.

### Hunting for Threats

Use the `hunt` skill to systematically search for malicious activity and threats. For example in Claude Code:

**Threat Hunting in PCAP:**

```
/suricata-analyze:hunt

Hunt for threats in suspicious-traffic.pcap
```

The AI agent will execute 10+ systematic hunting queries to detect C2 communication, data exfiltration, malicious domains, beaconing, and other threat indicators. A comprehensive threat hunting report will be generated with findings, affected hosts, and flow IDs for investigation.

**Threat Hunting in EVE Logs:**

```
/suricata-analyze:hunt

Look for compromised hosts in eve.json
```

The AI agent will hunt for indicators of compromise including suspicious user agents, connections to malicious TLDs, large data transfers, DNS anomalies, and beaconing patterns.

**What the Hunt Skill Detects:**
- C2 (Command & Control) communication patterns
- Data exfiltration attempts (large uploads)
- Suspicious user agents connecting to IP addresses
- Connections to high-risk TLDs (.xyz, .top, .cc, etc.)
- DNS tunneling and DGA domains
- Beaconing activity
- TLS/SSL anomalies (self-signed certs, IP-based connections)
- Internal reconnaissance and scanning
- HTTP method anomalies and web attacks
- Protocol anomalies and unusual port usage

## Best Practices

The Suricata Rules plugin enforces these best practices:

- **No warnings or errors** - All signatures are validated with `suricata-language-server`
- **No deprecated modifiers** - Content modifier keywords are not used
- **Clear messages** - Rule messages are concise (<100 chars) and descriptive
- **Proper metadata** - Includes `created_at`, `updated_at`, and `written_by` fields
- **Threshold configuration** - Repeated actions include thresholds to limit alerts
- **Domain transforms** - Domain matching uses proper transforms
- **Direction awareness** - Proper use of `$HOME_NET` and `$EXTERNAL_NET`

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

Apache 2.0 License. See [LICENSE](LICENSE) for details.

## About Stamus Networks

Stamus Networks is dedicated to providing advanced network security solutions. Learn more at [stamus-networks.com](https://www.stamus-networks.com/).

## Support

For issues or questions:
- Open an issue on GitHub
- Visit [Stamus Networks Support](https://www.stamus-networks.com/support)
