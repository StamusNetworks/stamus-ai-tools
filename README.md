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

## Installation

### Prerequisites

For the Suricata Rules plugin, you'll need:

- Python 3.x
- `suricata-language-server` (install via pip)

```bash
pip install suricata-language-server
```

If Suricata is not installed locally, you can use the containerized version with the `--container` flag.

### Installing the Claude Code Plugin

#### From Claude Code Marketplace

You can add the plugin directly from the Claude Code marketplace:
```
/plugin marketplace add StamusNetworks/stamus-ai-tools
```
Then you can install the Suricata Rules plugin:

```
/plugin install suricata-rules@stamus-ai-tools
```

#### Manual Installation

1. Clone this repository
2. Install the Suricata Rules plugin in Claude Code:

```bash
claude-code plugin install ./plugins/suricata-rules
```
### Installation for other AI agents


1. Clone this repository
2. Copy the directories containing the skills you want to use into your AI agent's plugin directory

For example, with OpenCode:

```bash
cp -r ./plugins/suricata-rules/* ~/.opencode/plugins/
```

## Usage

### Explaining Suricata Signatures

Use the `explain` skill to understand what a signature does. For example in Claude Code:

```
/suricata-rules:explain

[Paste your Suricata rule here]
```

The AI agent will provide a detailed breakdown of the signature's purpose, components, and threat context.

### Writing Suricata Signatures

Use the `writer` skill to create new signatures. For example in Claude Code:

```
/suricata-rules:writer

I need a signature to detect DNS queries to malicious-domain.com
```

The AI agent will generate a properly formatted signature, validate it, and ensure it follows best practices.

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
