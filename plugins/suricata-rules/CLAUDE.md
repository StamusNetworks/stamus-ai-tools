# Suricata Rules Plugin Instructions

This plugin provides specialized skills for working with Suricata network security signatures (also called rules).

## When to Use This Plugin

Automatically invoke the appropriate skill when users:

### Use the `suricata-rules:writer` skill when:
- Ask to write, create, or generate a Suricata signature/rule
- Want to detect specific network traffic patterns or threats
- Mention creating detection rules for network security
- Ask about writing rules for IDS/IPS systems
- Request help with Suricata rule syntax
- Want to detect specific protocols, domains, or attack patterns
- Ask to write policy violation rules
- Request rules for threat detection or network monitoring
- Mention flowbits, sticky buffers, or Suricata-specific features

**Examples:**
- "Write a Suricata rule to detect DNS queries to malicious-domain.com"
- "Create a signature for detecting TLS connections to a specific IP"
- "I need a rule to block HTTP traffic to a specific domain"
- "How do I write a Suricata signature for detecting SMB traffic?"
- "Generate a policy violation rule for detecting SSH on non-standard ports"

### Use the `suricata-rules:explain` skill when:
- User provides a Suricata signature and asks what it does
- User asks for clarification about a specific rule
- User wants to understand how a signature works
- User asks about the meaning of keywords in a signature
- User requests an explanation of rule components
- User wants to know what traffic a rule will match

**Examples:**
- "What does this Suricata rule do: alert http any any -> any any (msg:\"test\"; http.uri; content:\"/admin\"; sid:1;)"
- "Explain this signature to me"
- "What will this rule detect?"
- "What does the flow:established,to_server keyword mean?"
- "Can you break down this Suricata rule for me?"

## Key Concepts

- Suricata signatures are also referred to as "rules"
- They detect specific patterns in network traffic
- Common keywords: alert, flow, content, sid, rev, msg, http.uri, tls.sni, dns.query
- Signatures can be inbound or outbound
- Rules use sticky buffers to set matching context

## Proactive Behavior

When users mention Suricata, network detection, IDS/IPS rules, or show network security signatures:
1. Recognize this is likely a Suricata-related task
2. Invoke the appropriate skill automatically
3. Use `suricata-rules:writer` for creation tasks
4. Use `suricata-rules:explain` for understanding existing rules

Always prefer using these specialized skills over attempting to write or explain Suricata rules without them, as they contain essential domain knowledge, best practices, and validation tools.
