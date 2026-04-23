---
name: hunt-dns-tunnel
description: Hunt for DNS tunneling in Suricata eve.json. Detects two archetypes — (1) TXT base64 file exfiltration with sequential chunked payloads, (2) dnscat2-style C2 with hex-encoded QNAME subdomain labels and multi-type channel rotation (MX/TXT/CNAME). Reconstructs and decodes exfiltrated payloads or extracts raw session bytes, looks up flow sizes from event_type:flow, and prints a structured report with an event table. Use when asked to find suspicious DNS, detect DNS tunneling, or decode DNS-tunneled data from a Suricata log file.
argument-hint: [path to eve.json, default: eve.json in current directory] [output file, default: tunneled_payload.txt alongside eve.json]
allowed-tools: Bash, Read, Write, Glob
---

# Hunt DNS Tunneling in Suricata eve.json

Detect, confirm, decode, and report DNS tunneling from a Suricata `eve.json` log.

Two archetypes are covered:

| Archetype | Channel | Payload encoding | Tool example |
|---|---|---|---|
| **File exfil** | TXT rdata only | `[8-hex seq][base64 chunk]` per response | Custom scripts |
| **C2 tunnel** | MX + TXT + CNAME QNAME labels | hex-encoded binary in subdomain labels | dnscat2 |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `output_file` — Output path for decoded/extracted payload (default: `tunneled_payload.txt` next to `eve.json`)

---

## Step 1 — Locate and size the file

```bash
wc -l eve.json
grep '"event_type":"dns"' eve.json | wc -l
```

Suricata v3 DNS format — nested arrays in every event:
- `dns.type` — `"request"` or `"response"`
- `dns.queries[].rrname` / `.rrtype` — query name and record type
- `dns.answers[].rrname` / `.rrtype` / `.rdata` — response data
- `dns.rcode` — `NOERROR`, `NXDOMAIN`, etc.
- `app_proto` is **not emitted** on `dns` event_type records — it is implied by the event type itself; use `"dns"` as the value when reporting.

---

## Step 2 — First-pass statistical analysis

Single Python pass collecting all indicators at once:

```python
import json, collections, math

def entropy(s):
    freq = collections.Counter(s.lower())
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

qtypes = collections.Counter()
domain_freq = collections.Counter()
long_domains = []
high_entropy = []
nxd_sources = collections.Counter()
unusual = []
first_ts = last_ts = None

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns':
            continue
        ts = e.get('timestamp', '')
        if not first_ts or ts < first_ts: first_ts = ts
        if not last_ts or ts > last_ts: last_ts = ts
        dns = e['dns']
        dtype = dns.get('type', '')
        src = e.get('src_ip', '')

        for q in dns.get('queries', []):
            name = q.get('rrname', '')
            rtype = q.get('rrtype', '')
            qtypes[rtype] += 1
            domain_freq[name] += 1
            labels = name.split('.')
            max_label = max(len(lb) for lb in labels) if labels else 0
            if len(name) > 50 or max_label > 30:
                long_domains.append((name, rtype, src, len(name), max_label))
            subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else labels[0]
            if subdomain and len(subdomain) > 6 and entropy(subdomain) > 3.5:
                high_entropy.append((entropy(subdomain), name, rtype, src))
            if rtype in ('TXT', 'MX', 'CNAME', 'NULL', 'ANY', 'HINFO', 'SRV', 'DNSKEY', 'DS', 'NAPTR'):
                unusual.append((rtype, name, src))

        if dtype == 'response' and dns.get('rcode') == 'NXDOMAIN':
            nxd_sources[e.get('dest_ip', '')] += 1

    except:
        pass
```

**Archetype 1 — file exfil red flags:**
- TXT > 20% of all queries is suspicious; > 50% is highly indicative
- Single domain dominates TXT volume by a large margin
- Consistent flat query rate (e.g. 78/min across 60 minutes) — automated tool

**Archetype 2 — C2 tunnel (dnscat2) red flags:**
- MX + TXT + CNAME together account for > 40% of DNS traffic
- Long domains: many FQDNs > 50 chars, individual labels > 30 chars
- All subdomains of an apex domain are pure lowercase hex strings
- Apex domain uses IDN/Punycode encoding (`xn--…`) — obfuscation
- Client queries an external resolver directly (e.g. `8.8.8.8`) — bypasses local DNS monitoring

---

## Step 3 — Identify tunnel archetype and deep-dive

### Archetype 1 — TXT base64 file exfil

Collect TXT rdata samples and check for `[8-hex][base64]` structure:

```python
for line in open('eve.json'):
    e = json.loads(line)
    dns = e.get('dns', {})
    if dns.get('type') == 'response':
        for ans in dns.get('answers', []):
            if ans.get('rrtype') == 'TXT' and 'suspectdomain.com' in ans.get('rrname', ''):
                print(ans.get('rdata', '')[:120])
```

Signatures in TXT rdata:
- `00000000<base64>`, `00000001<base64>`, … — chunked sequential file transfer
- Pure base64 without prefix — raw encoded data
- Hex-encoded binary
- Plaintext commands/responses — interactive shell (dnscat2 unencrypted)

Also scan all TXT rdata (any domain) for high-value content indicators:

```python
import json, re

UA_PATTERN = re.compile(r'\b(curl|wget|python|powershell)\b', re.IGNORECASE)
FILE_PATTERN = re.compile(r'\b\w[\w\-. ]*\.(exe|bat|ps1|sh|ppt|pptx|doc|docx|xls|xlsx)\b', re.IGNORECASE)

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        if dns.get('type') == 'response':
            for ans in dns.get('answers', []):
                if ans.get('rrtype') != 'TXT': continue
                rdata = ans.get('rdata', '')
                flags = []
                if len(rdata) > 100:
                    flags.append(f'LONG({len(rdata)})')
                if UA_PATTERN.search(rdata):
                    flags.append('USER-AGENT:' + UA_PATTERN.search(rdata).group())
                if FILE_PATTERN.search(rdata):
                    flags.append('FILENAME:' + FILE_PATTERN.search(rdata).group())
                if flags:
                    print(f'[{", ".join(flags)}] {ans.get("rrname","")}')
                    print(f'  rdata: {rdata}')
    except:
        pass
```

### Archetype 2 — dnscat2 QNAME hex C2

Collect all queries to the apex domain:

```python
import json, collections

APEX = 'suspect.click'   # replace with identified apex
subdomains = collections.Counter()
src_ips = set()
resolver_ips = set()
rdata_samples = []

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        for q in dns.get('queries', []):
            if APEX in q.get('rrname', ''):
                subdomains[q['rrname']] += 1
                src_ips.add(e.get('src_ip', ''))
                resolver_ips.add(e.get('dest_ip', ''))
        if dns.get('type') == 'response':
            for ans in dns.get('answers', []):
                if APEX in ans.get('rrname', '') and ans.get('rdata'):
                    rdata_samples.append(ans.get('rdata', ''))
    except:
        pass
```

QNAME subdomain structure (dnscat2 protocol):
```
[pkt-id 2B][msg-type 1B][session-id 2B][encrypted payload ...].apex.tld
```
- `msg-type`: `00`=SYN, `01`=MSG, `02`=FIN, `03`=PING
- Labels split at 63-char DNS limit; flatten by removing dots before parsing
- MX rdata and CNAME targets carry server→client data in the same hex format
- Responses end with a fixed `ffff…` seq/ack trailer

---

## Step 4 — Decode payload

### Archetype 1 — reconstruct base64 file

```python
import json, base64

chunks = {}
for line in open('eve.json'):
    e = json.loads(line)
    dns = e.get('dns', {})
    if dns.get('type') == 'response':
        for ans in dns.get('answers', []):
            if ans.get('rrtype') == 'TXT' and 'suspectdomain.com' in ans.get('rrname', ''):
                raw = ans.get('rdata', '')
                if len(raw) >= 8:
                    try:
                        seq = int(raw[:8], 16)
                        chunks[seq] = raw[8:]
                    except ValueError:
                        pass

sorted_keys = sorted(chunks.keys())
full_b64 = ''.join(chunks[k] for k in sorted_keys)
decoded = base64.b64decode(full_b64 + '==')
print(f'Chunks: {len(chunks)}, seq range: {min(sorted_keys)}-{max(sorted_keys)}')
print(f'Decoded: {len(decoded)} bytes, magic: {decoded[:4].hex()}')
```

Common magic bytes:

| Hex | File type |
|---|---|
| `ffd8ffe0` / `ffd8ffe1` | JPEG image |
| `89504e47` | PNG image |
| `25504446` | PDF |
| `504b0304` | ZIP / Office document |
| `7f454c46` | ELF binary (Linux) |
| `4d5a9000` | PE/EXE (Windows) |
| `1f8b0800` | gzip archive |

### Archetype 2 — extract dnscat2 session bytes

Parse all tunnel packets by session, separating client→server (Q) and server→client (R) bytes:

```python
import json, collections, struct

APEX = 'suspect.click'
TYPE_NAMES = {0: 'SYN', 1: 'MSG', 2: 'FIN', 3: 'PING'}
sessions = collections.defaultdict(lambda: {'Q': [], 'R': []})

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'dns': continue
        dns = e['dns']
        dtype = dns.get('type', '')
        ts = e.get('timestamp', '')

        for q in dns.get('queries', []):
            name = q.get('rrname', '')
            if APEX not in name: continue
            hex_data = name.replace('.' + APEX, '').replace('.', '')
            if len(hex_data) >= 10:
                raw = bytes.fromhex(hex_data)
                sess = raw[3:5].hex()
                sessions[sess]['Q'].append({'type': raw[2], 'data': raw[5:], 'ts': ts})

        if dtype == 'response':
            for ans in dns.get('answers', []):
                if APEX not in ans.get('rrname', ''): continue
                rdata = ans.get('rdata', '').replace('.' + APEX, '').replace('.', '')
                if len(rdata) >= 10:
                    raw = bytes.fromhex(rdata)
                    sess = raw[3:5].hex()
                    sessions[sess]['R'].append({'type': raw[2], 'data': raw[5:], 'ts': ts})
    except:
        pass

# Check SYN packets for session name
for sid, pkts in sessions.items():
    for p in pkts['Q'] + pkts['R']:
        if p['type'] == 0 and len(p['data']) >= 4:
            isn = struct.unpack('>H', p['data'][0:2])[0]
            name = p['data'][4:].split(b'\x00')[0].decode('utf-8', errors='replace')
            print(f'Session {sid}: ISN={isn:#06x} name={repr(name)}')
```

dnscat2 sessions are encrypted by default — raw bytes will be binary. Extract and save them; do not attempt to decrypt without the session key.

---

## Step 5 — Assess query timing and rate

```python
minute_counts = collections.Counter()
for line in open('eve.json'):
    e = json.loads(line)
    if e.get('event_type') != 'dns': continue
    dns = e['dns']
    if dns.get('type') == 'request':
        for q in dns.get('queries', []):
            if 'suspectdomain' in q.get('rrname', ''):
                minute_counts[e.get('timestamp', '')[:16]] += 1

for ts, cnt in sorted(minute_counts.items()):
    print(f'{ts}: {cnt}')
```

A flat, consistent rate across many minutes = automated tool. A short burst at very high rate (e.g. 300+/min over 90 seconds) = dnscat2 retransmit behavior.

---

## Step 6 — Look up flow sizes from event_type:flow

For each representative flow_id in the example events, find the matching `event_type:flow` record to get bytes transferred:

```python
import json

target_flows = {339169965393785, 287532207143557}   # replace with actual IDs

for line in open('eve.json'):
    try:
        e = json.loads(line)
        if e.get('event_type') != 'flow': continue
        if e.get('flow_id') in target_flows:
            f = e.get('flow', {})
            print(f"flow_id={e['flow_id']} "
                  f"toserver={f.get('bytes_toserver')} "
                  f"toclient={f.get('bytes_toclient')} "
                  f"app_proto={e.get('app_proto')}")
    except:
        pass
```

Report flow size as `N B (→toserver ←toclient)` in the events table.

---

## Step 7 — Save decoded payload

Write decoded/extracted data to disk with `.txt` extension so it is not accidentally executed:

```python
# Archetype 1 — binary payload
with open('tunneled_payload.txt', 'wb') as f:
    f.write(decoded)

# Archetype 2 — session hex dump
with open('tunneled_payload.txt', 'w') as f:
    f.write('DNSCAT2 TUNNEL SESSIONS — RAW EXTRACTED DATA\n')
    for sid, pkts in sorted(sessions.items()):
        q_data = b''.join(p['data'] for p in sorted(pkts['Q'], key=lambda x: x['ts']) if p['type'] == 1)
        r_data = b''.join(p['data'] for p in sorted(pkts['R'], key=lambda x: x['ts']) if p['type'] == 1)
        f.write(f'\n--- Session {sid} ---\n')
        f.write(f'  C->S bytes: {len(q_data)}\n')
        f.write(f'  S->C bytes: {len(r_data)}\n')
        for i in range(0, len(q_data), 32):
            f.write(f'  C->S {i:04x}: {q_data[i:i+32].hex()}\n')
        for i in range(0, len(r_data), 32):
            f.write(f'  S->C {i:04x}: {r_data[i:i+32].hex()}\n')
```

**Never execute, open, or run the decoded payload.**

---

## Step 8 — Print report

Print the full report to the terminal. Always include the events table.

**CRITICAL — dns.rrname and dns.rdata must always be printed in full, never truncated.**
- `dns.rrname` may be up to 253 characters (multi-label hex domains in dnscat2 or iodine uploads) — print every character.
- `dns.rdata` for TXT may be up to 256 characters (iodine A–P base16 or base64 chunks) — print every character.
- Never use `[:N]`, `...`, or ellipsis to shorten these fields in the table or anywhere in the report.
- If a cell value is long, let the table row wrap — do not abbreviate the data.

```
╔══════════════════════════════════════════════════════════════════════╗
║         DNS TUNNEL HUNT REPORT — Suricata eve.json                   ║
╠══════════════════════════════════════════════════════════════════════╣
║  File    : /path/to/eve.json                                         ║
║  Lines   : N total  |  N DNS events                                  ║
║  Window  : YYYY-MM-DDTHH:MM  →  HH:MM  (~N seconds/minutes)         ║
╠══════════════════════════════════════════════════════════════════════╣
║  VERDICT :  CONFIRMED — [ARCHETYPE] DETECTED                        ║
╚══════════════════════════════════════════════════════════════════════╝

── DNS RESOLVERS ──────────────────────────────────────────────────────
  x.x.x.x     description (local resolver / Google DNS / C2 auth NS)

── VICTIM IPs ─────────────────────────────────────────────────────────
  x.x.x.x     description

── TUNNEL DOMAIN / SESSIONS ───────────────────────────────────────────
  [domain / session summary]

── EXAMPLE TUNNEL EVENTS ──────────────────────────────────────────────

| # | event_type | app_proto | src_ip | dest_ip | flow_id | flow size | rrtype | dns.rrname (query) — FULL, never truncated | dns.rdata (answer) — FULL, never truncated | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | dns | dns * | ... | ... | ... | N B (→N ←N) | ... | full rrname value | full rdata value | ... |
...

  rrname structure: [pkt-id 2B][msg-type 1B][session-id 2B][payload ...].apex.tld
  rdata  structure: [pkt-id 2B][msg-type 1B][session-id 2B][payload ...][seq/ack in brackets]

  † / ‡ footnotes as needed
  * app_proto not emitted by Suricata on dns event_type; implied by event_type itself

── INDICATOR CHECKLIST ────────────────────────────────────────────────
  [FAIL/PASS]  indicator  →  observed value

── OUTPUT FILE ────────────────────────────────────────────────────────
  /path/to/tunneled_payload.txt
```

---

## Checklist — tunneling indicators

| Indicator | Archetype | How to detect |
|---|---|---|
| TXT > 20% of DNS volume | File exfil | Query type distribution |
| Single domain dominates TXT | File exfil | Top queried domains |
| Sequential hex+base64 in TXT rdata | File exfil | `00000000<b64>` pattern in rdata |
| Base64 decodes to known file magic | File exfil | Check first 4 bytes after decode |
| Consistent flat query rate | File exfil | Per-minute count over many minutes |
| MX + TXT + CNAME combined > 40% | C2 tunnel | Query type distribution |
| Long FQDN labels (> 30 chars) | C2 tunnel | Max label length per query |
| All subdomains are pure hex strings | C2 tunnel | Subdomain character set check |
| dnscat2 SYN handshake in QNAME | C2 tunnel | `type=00` byte in hex subdomain |
| Multiple concurrent sessions | C2 tunnel | Distinct session-id bytes (offset 3–4) |
| IDN / Punycode apex domain | C2 tunnel | `xn--` prefix in apex domain |
| Client bypasses local resolver | C2 tunnel | Queries direct to 8.8.8.8 or similar |
| Rotating A record IPs | Both | Many distinct A records per domain |
| No Suricata signatures fired | Both | Empty fast.log for tunnel domain |
| TXT rdata longer than 100 chars | Both | `len(rdata) > 100` in TXT answers |
| User-agent strings in TXT rdata | Both | Grep rdata for `curl`, `wget`, `python`, `powershell` (case-insensitive) |
| Executable or document filenames in TXT rdata | Both | Grep rdata for `.exe`, `.bat`, `.ps1`, `.sh`, `.ppt`, `.doc`, `.xls` (case-insensitive) |
