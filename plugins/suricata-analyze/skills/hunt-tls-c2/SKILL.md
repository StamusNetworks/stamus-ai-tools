---
name: hunt-tls-c2
description: 'Hunt for malicious TLS in Suricata eve.json (event_type:tls). Detects DGA / high-entropy / word-list SNI, IP-literal and malformed SNI, high-abuse TLDs (.xyz/.cc/.cyou/.sbs/.cfd/.top/.online/.icu/etc.), IP-literal and invalid cert Subject/Issuer CN, self-signed and OpenSSL-default certificates (subject==issuer, "Internet Widgits", "Default City", CN=localhost/0.0.0.0), then correlates each suspicious SNI to event_type:flow via flow_id to surface long-lived C2 sessions (flow.age > 5 min) and repetitive single-destination beacons, and pivots on shared JA3/JA4 fingerprints. Prints a structured report with an evidence table. Use when asked to hunt malicious/C2/DGA TLS, find suspicious SNI or certificates, or triage HTTPS beaconing in a Suricata log.'
argument-hint: "[path to eve.json, default: eve.json in current directory] [output file, default: tls-hunt-report.txt alongside eve.json]"
allowed-tools: "Bash, Read, Write, Glob"
---

# Hunt Malicious TLS / C2 in Suricata eve.json

Detect, correlate, and report suspicious TLS activity from a Suricata `eve.json` log.
The hunt fuses **name-based** signals (SNI, certificate Subject/Issuer) with
**behavioural** signals (flow age, repetition, byte volume) and **fingerprint**
signals (JA3/JA4), because any single axis produces false positives on modern CDNs.

Archetypes covered:

| # | Archetype | Primary signal | Example |
|---|---|---|---|
| 1 | **Random-alnum DGA SNI** | high-entropy 2LD, no vowels, digit-mix | `jzc65r6hsglcl7d2tk.com` |
| 2 | **Word-list / pronounceable DGA** | non-dictionary, heavy repetition, single dest | `robwassotdint.ru`, `junudorij.com` |
| 3 | **IP-literal SNI** | SNI is an IPv4/IPv6 (RFC 6066 violation) | `sni=45.153.243.93` |
| 4 | **Invalid / malformed SNI** | underscore, space, single-label, `localhost` | `sni=localhost` |
| 5 | **Suspicious-TLD SNI** | high-abuse TLD | `*.top`, `*.cc`, `*.cyou`, `*.sbs`, `*.cfd` |
| 6 | **Anomalous certificate** | IP-literal CN, self-signed (subject==issuer), OpenSSL defaults | `CN=0.0.0.0`, `O=Internet Widgits` |
| 7 | **Long-lived C2 flow** | `flow.age > 300 s` on a suspicious SNI | held-open TLS keepalive |
| 8 | **Repetitive beacon** | many connections, single dest IP | 7,609 conns → 1 IP |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `output_file` — Path for the written report (default: `tls-hunt-report.txt` next to `eve.json`)

---

## Step 1 — Locate and size the file

```bash
wc -l eve.json
grep -c '"event_type":"tls"' eve.json
grep -m1 '"event_type":"tls"' eve.json | python3 -m json.tool
```

Suricata TLS event fields (nested under `tls`). Which fields appear depends on the
`eve-log → tls` config: **default** (always), **extended: yes**, and **custom:** (opt-in
per field). Any field may be absent on a given record (e.g. resumed sessions carry no
certificate, TLS 1.3 hides the cert, ClientHello-only flows have no SNI).

Server Name Indication:
- `tls.sni` *(default)* — Server Name Indication host from the ClientHello. May be absent.

Negotiated connection:
- `tls.version` *(default)* — negotiated version string: `TLS 1.3`, `TLS 1.2`, `TLSv1`,
  `SSLv3`, `SSLv2`, or `UNDETERMINED`.
- `tls.session_resumed` *(default)* — `true` when the handshake resumed a prior session
  (an abbreviated handshake — **no certificate is exchanged**, so cert fields are absent).

Leaf-certificate identity:
- `tls.subject` *(default)* — leaf certificate Subject DN string (parse `CN=`, `O=`, `Email=` out of it).
- `tls.issuerdn` *(default)* — leaf certificate Issuer DN string (equals `subject` ⇒ self-signed).
- `tls.serial` *(extended)* — certificate serial number (colon-hex).
- `tls.fingerprint` *(extended)* — SHA1 fingerprint of the leaf certificate (colon-hex).
- `tls.notbefore` *(extended)* — certificate validity start (ISO 8601).
- `tls.notafter` *(extended)* — certificate validity end (ISO 8601). Compare with
  `timestamp` to catch expired / not-yet-valid / absurdly-long-lived certs.
- `tls.subjectaltname[]` *(custom, newer builds)* — Subject Alternative Names, when present.

TLS fingerprints (each is opt-in via `custom:` and its feature must be enabled):
- `tls.ja3` — client fingerprint **object**: `{ "hash": <md5>, "string": <raw ja3> }`.
- `tls.ja3s` — server fingerprint **object**: `{ "hash": <md5>, "string": <raw ja3s> }`.
- `tls.ja4` — client **JA4** fingerprint string (Suricata 7.0.3+); primary pivot key here.

Raw certificate material (custom / file-store logging):
- `tls.certificate` *(custom)* — base64 DER of the leaf certificate.
- `tls.chain[]` *(custom)* — array of the presented chain; each entry carries
  `subject`, `issuerdn`, `fingerprint` (and base64 `data` when configured).

Note when parsing:
- `tls.ja3` / `tls.ja3s` are **objects**, not strings — read `tls.ja3.hash` (guard for the
  field being `null` or absent). `tls.ja4` **is** a plain string.
- DN strings (`subject`, `issuerdn`) are free-form and may contain commas inside values;
  the `cn_of()` helper's `CN=([^,/]+)` is a pragmatic extraction, not a full RFC 4514 parse.

Top-level fields on every TLS record (siblings of `tls`, not under it):
- `flow_id` — **join key** to the matching `event_type:flow` record (age, bytes, state).
- `src_ip` / `src_port` / `dest_ip` / `dest_port` / `proto` / `ip_v`
- `timestamp`, `pcap_cnt`, `pkt_src`, `tx_id`, and `community_id` / `metadata` when enabled.
- `app_proto` is **not** emitted on `tls` records — it is implied by the event type; report as `"tls"`.

**Grep is your friend for large files** — always `grep '"event_type":"tls"'` (or `flow`)
to pre-filter lines before `json.loads`, so a multi-GB `eve.json` streams in seconds.

---

## Step 2 — First-pass: score every SNI + certificate

Single Python pass. Defines the reusable helpers used by the whole skill: entropy,
registrable-domain extraction, IP detection, CN parsing, malformed-host test, the
DGA scorer, and the high-abuse TLD set.

```python
import json, collections, math, re

EVE = 'eve.json'

# --- high-abuse TLDs (edit freely; the user-named ones are first) ---
SUSP_TLD = {
 'xyz','cc','cyou','sbs','cfd','top','icu','online','website','club','work','surf',
 'quest','monster','rest','live','fit','cam','bar','buzz','pw','tk','ml','ga','cf',
 'gq','su','men','loan','download','stream','gdn','racing','win','review','date',
 'party','science','link','click','space','fun','life','store','site','kim','mom',
 'lol','beauty','makeup','skin','hair','autos','boats','cheap','cricket','accountant',
 'faith','trade','webcam','uno','zip','mov','rip','wtf','ooo','shop'}

# --- obvious-benign registrable domains (tagged, never used to hide a finding) ---
BENIGN = {'microsoft.com','google.com','bing.com','live.com','ipify.org','windows.com',
 'msftncsi.com','office.com','office365.com','gstatic.com','googleapis.com','apple.com',
 'icloud.com','mozilla.org','mozilla.com','cloudflare.com','akamai.net','akamaized.net',
 'amazonaws.com','ssl-images-amazon.com','digicert.com','windowsupdate.com','msn.com',
 'skype.com','facebook.com','fbcdn.net','doubleclick.net','ytimg.com','azureedge.net',
 'msedge.net','microsoftonline.com','linkedin.com','yahoo.com','oracle.com','cisco.com'}

MULTI_TLD = {'co.uk','com.br','co.za','gen.tr','com.au','co.jp','co.in','org.uk',
 'com.tr','net.br','com.cn','com.mx','co.kr','com.tw','ne.jp','or.jp'}
VOWELS = set('aeiou')
IPV4 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
IPV6 = re.compile(r'^[0-9A-Fa-f:]+:[0-9A-Fa-f:]+$')
HOST_OK = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9\-_.]*[A-Za-z0-9])?$')

def entropy(s):
    if not s: return 0.0
    f = collections.Counter(s); n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in f.values())

def registrable(host):
    host = host.rstrip('.').lower(); labels = host.split('.')
    if len(labels) < 2: return host, host
    last2 = '.'.join(labels[-2:])
    if last2 in MULTI_TLD and len(labels) >= 3:
        return labels[-3], '.'.join(labels[-3:])
    return labels[-2], last2                      # (2LD label, registrable domain)

def tld_of(host):
    host = host.rstrip('.').lower()
    return host.rsplit('.', 1)[-1] if '.' in host else ''

def is_ip(s):
    if not s: return False
    if IPV4.match(s): return all(0 <= int(o) <= 255 for o in s.split('.'))
    return bool(':' in s and IPV6.match(s))

def cn_of(dn):
    m = re.search(r'CN=([^,/]+)', dn or '')
    return m.group(1).strip() if m else ''

def invalid_host(s):
    if not s or is_ip(s): return False
    if len(s) > 253 or ' ' in s or '\t' in s: return True
    if not HOST_OK.match(s): return True
    if '_' in s or '.' not in s or '..' in s: return True   # underscore/single-label
    return False

def max_consonant_run(s):
    run = mx = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS: run += 1; mx = max(mx, run)
        else: run = 0
    return mx

def dga_score(label):
    """0-8 randomness score for a 2LD label."""
    if not label: return 0
    L = len(label); ent = entropy(label)
    alpha = [c for c in label if c.isalpha()]
    digits = [c for c in label if c.isdigit()]
    vr = sum(c in VOWELS for c in alpha)/len(alpha) if alpha else 0
    dr = len(digits)/L; sc = 0
    if L >= 10: sc += 1
    if L >= 16: sc += 1
    if ent >= 3.2: sc += 1
    if ent >= 3.8: sc += 1
    if alpha and vr < 0.30: sc += 1
    if vr == 0 and len(alpha) >= 5: sc += 1
    if dr >= 0.20 and len(digits) >= 2: sc += 1
    if max_consonant_run(label) >= 5: sc += 1
    return sc

# --- aggregation ---
dom = collections.defaultdict(lambda: {'count':0,'label':'','score':0,'flows':set(),
      'dst':collections.Counter(),'src':collections.Counter(),
      'ja4':collections.Counter(),'first':None,'last':None,'sni':collections.Counter()})
sni_ip = collections.Counter(); subj_ip = collections.Counter(); iss_ip = collections.Counter()
sni_invalid = collections.Counter()
sni_susptld = collections.Counter(); subj_susptld = collections.Counter(); iss_susptld = collections.Counter()
selfsigned = collections.Counter()          # subject == issuer
ja4_domains = collections.defaultdict(set)   # ja4 -> {registrable domains}
tot = with_sni = 0

for line in open(EVE):
    if '"event_type":"tls"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'tls': continue
    tls = e.get('tls', {})
    sni = (tls.get('sni') or '').strip()
    subj = tls.get('subject') or ''; iss = tls.get('issuerdn') or ''
    scn = cn_of(subj); icn = cn_of(iss)
    ja4 = tls.get('ja4') or ''
    src = e.get('src_ip',''); dst = e.get('dest_ip',''); ts = e.get('timestamp',''); fid = e.get('flow_id')
    tot += 1
    if subj and subj == iss: selfsigned[scn or subj] += 1     # self-signed cert

    if sni:
        with_sni += 1
        if is_ip(sni): sni_ip[sni] += 1
        else:
            if invalid_host(sni): sni_invalid[sni] += 1
            t = tld_of(sni)
            if t in SUSP_TLD: sni_susptld[t] += 1
            lbl, reg = registrable(sni)
            d = dom[reg]; d['count'] += 1; d['label'] = lbl
            d['dst'][dst] += 1; d['src'][src] += 1; d['sni'][sni] += 1
            if fid: d['flows'].add(fid)
            if ja4: d['ja4'][ja4] += 1; ja4_domains[ja4].add(reg)
            if not d['first'] or ts < d['first']: d['first'] = ts
            if not d['last']  or ts > d['last']:  d['last']  = ts

    if scn:
        if is_ip(scn): subj_ip[scn] += 1
        elif tld_of(scn) in SUSP_TLD: subj_susptld[tld_of(scn)] += 1
    if icn:
        if is_ip(icn): iss_ip[icn] += 1
        elif tld_of(icn) in SUSP_TLD: iss_susptld[tld_of(icn)] += 1

for reg, d in dom.items():
    d['score'] = dga_score(d['label'])

print(f"TLS events: {tot} | with SNI: {with_sni} | distinct reg domains: {len(dom)}")
print(f"IP-SNI: {sum(sni_ip.values())}  invalid-SNI: {sum(sni_invalid.values())}  "
      f"susp-TLD SNI: {sum(sni_susptld.values())}")
print(f"IP subject-CN: {sum(subj_ip.values())}  IP issuer-CN: {sum(iss_ip.values())}  "
      f"self-signed: {sum(selfsigned.values())}")
```

**Red flags:**
- Many registrable domains with `dga_score >= 5` (random-alnum DGA).
- Any `sni_ip`, `subj_ip`, `iss_ip` entries (IP literals in name fields — abnormal).
- Any `sni_invalid` (malformed hostnames — `localhost`, underscores, single labels).
- Large `sni_susptld` counts, especially on `.top/.online/.icu/.xyz/.cc/.cyou/.sbs/.cfd`.
- `subj_susptld` and `iss_susptld` with **matching counts per TLD** → self-signed C2 certs.

---

## Step 3 — Deep-dive per archetype

### 3a — Random-alnum DGA SNI (score ≥ 5)

```python
scored = sorted(((d['score'], reg, d['label'], d['count'], len(d['flows']), d['dst'].most_common(2))
                 for reg, d in dom.items()), reverse=True)
for sc, reg, lbl, cnt, nflow, topdst in scored:
    if sc < 5: break
    print(f"sc={sc} {reg:34} conns={cnt:>4} flows={nflow:>4} dst={topdst}")
```
Random-alnum DGA domains are usually hit **once each** but still complete a real TLS
handshake — so the malware resolved them and reached live C2. Aggregate their
**dest IPs** (concentration on a few VPS/hosting IPs) and **src IPs** (infected hosts).

### 3b — Word-list / pronounceable DGA (repetition, single dest)

These score LOW on entropy (they look pronounceable) but repeat heavily to **one** IP.
Detect them behaviourally in Step 4 (high `count`, `ndst == 1`, not in `BENIGN`).
Classic families: Necurs/Suppobox-style concatenated English words on `.ru`/`.com`
(`robwassotdint.ru`, `encitimefoan.ru`, `bulighhesin.ru`, `kedfortmoleft.ru`).

### 3c — IP-literal & invalid SNI

```python
print("IP-SNI:", sni_ip.most_common(20))
print("invalid SNI:", sni_invalid.most_common(20))
```
- IP-SNI to `:443` at the same IP → direct-to-IP C2 with no hostname.
- IP-SNI where SNI ≠ dest (e.g. SNI is an IP but dest is O365 on `:993`) → anomalous tool.
- `sni=localhost` / underscore labels → malformed; note Akamai `*.akamaihd.net`
  client-tons names use underscores and are a **benign false positive**.

### 3d — Anomalous certificates

```python
print("IP subject-CN:", subj_ip.most_common(20))
print("IP issuer-CN :", iss_ip.most_common(20))
print("self-signed (subject==issuer) top CNs:")
for cn, c in selfsigned.most_common(30): print(f"  {c:>5}  {cn}")
```
Grep the raw certs for OpenSSL/default templates and word-DGA CNs:
```bash
grep '"event_type":"tls"' eve.json | grep -Eo '"(subject|issuerdn)":"[^"]*"' \
 | grep -iE 'Internet Widgits|Default City|Default Company|CN=localhost|CN=0\.0\.0\.0' | sort | uniq -c | sort -rn | head
```
Split results into **malicious** (subject==issuer self-signed, IP/DGA CN, OpenSSL
defaults) vs **benign appliances** (Dahua/Hikvision DVRs with `CN=192.168.x`, ISP CPE
with a real root CA, `CN=0.0.0.0` from a telco CA). Report both, but label the FPs.

### 3e — Suspicious-TLD SNI

```python
for t, c in sni_susptld.most_common():
    print(f".{t:8} {c:>6} conns")
susp = sorted(((d['count'], reg, tld_of(reg)) for reg, d in dom.items()
               if tld_of(reg) in SUSP_TLD), reverse=True)
for cnt, reg, t in susp[:40]:
    print(f"  {reg:34.34} .{t:8} conns={cnt}")
```

---

## Step 4 — Correlate suspicious SNIs to event_type:flow

Pick the suspicious set (DGA score ≥ 5, OR ≥ 100 conns and not benign, OR
suspicious-TLD, OR IP/invalid SNI), map every `flow_id` to its domain, then stream
the `flow` records once to pull `flow.age`, byte counts, and state.

```python
RANDOM = {reg for reg, d in dom.items() if d['score'] >= 5}
REPEAT = {reg for reg, d in dom.items() if d['count'] >= 100 and reg not in BENIGN and reg not in RANDOM}
TLDSET = {reg for reg in dom if tld_of(reg) in SUSP_TLD}
susp = RANDOM | REPEAT | TLDSET

flow2dom = {fid: reg for reg in susp for fid in dom[reg]['flows']}
flowinfo = {}
for line in open(EVE):
    if '"event_type":"flow"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'flow' or e.get('flow_id') not in flow2dom: continue
    f = e.get('flow', {})
    flowinfo[e['flow_id']] = {'age': f.get('age'), 'state': f.get('state'),
        'bts': f.get('bytes_toserver'), 'btc': f.get('bytes_toclient'),
        'pts': f.get('pkts_toserver'), 'ptc': f.get('pkts_toclient'), 'dst': e.get('dest_ip')}

import statistics
rows = []
for reg in susp:
    fids = [f for f in dom[reg]['flows'] if f in flowinfo]
    ages = [flowinfo[f]['age'] for f in fids if flowinfo[f]['age'] is not None]
    rows.append({'reg': reg, 'conns': dom[reg]['count'], 'ndst': len(dom[reg]['dst']),
        'nflow': len(dom[reg]['flows']), 'maxage': max(ages) if ages else 0,
        'medage': int(statistics.median(ages)) if ages else 0,
        'longflows': sum((flowinfo[f]['age'] or 0) > 300 for f in fids),
        'score': dom[reg]['score'], 'tld': tld_of(reg),
        'topdst': dom[reg]['dst'].most_common(3),
        'first': dom[reg]['first'], 'last': dom[reg]['last']})

# Finding A — long-lived (flow.age > 5 min)
print("\n== FINDING A: flow.age > 300s ==")
for r in sorted((r for r in rows if r['longflows']), key=lambda r: -r['maxage'])[:40]:
    print(f"{r['reg']:34.34} conns={r['conns']:>5} longfl={r['longflows']:>4} "
          f"maxage={r['maxage']:>7}s ndst={r['ndst']:>3} {r['topdst']}")

# Finding B — repetitive single-dest beacons (CDN filtered out by ndst)
print("\n== FINDING B: repetitive, ndst==1 (beacons) ==")
for r in sorted((r for r in rows if r['ndst'] == 1), key=lambda r: -r['conns'])[:40]:
    win = f"{(r['first'] or '')[:16]}->{(r['last'] or '')[:16]}"
    print(f"{r['reg']:34.34} conns={r['conns']:>6} maxage={r['maxage']:>6}s score={r['score']} {win}")
```

- **Finding A** — `flow.age > 300 s` on a suspicious SNI = held-open C2 (keepalive,
  interactive shell, or long download). Report `maxage`, bytes, dest.
- **Finding B** — high `count` with `ndst == 1` = beacon to a single C2 IP.
  `ndst` (distinct dest IPs) is the key CDN discriminator: **1 = beacon**, dozens = CDN.
- Report flow size as `N B (→toserver ←toclient)`.

---

## Step 5 — JA3 / JA4 fingerprint pivot

Certificates and domains rotate; the malware's TLS stack usually does not. A single
JA4 shared across several unrelated domains ties them to one tool/family.

```python
print("JA4 shared across multiple registrable domains:")
for ja4, regs in sorted(ja4_domains.items(), key=lambda kv: -len(kv[1])):
    if len(regs) >= 3:
        print(f"  {ja4}  ({len(regs)} domains)  e.g. {sorted(regs)[:6]}")
```
Note JA4s that appear on already-confirmed C2 domains, then sweep for any other domain
sharing that fingerprint — it is likely the same actor even if the name looks benign.

---

## Step 6 — Pull evidence rows (TLS ↔ flow) for the report

For each headline finding grab one full TLS event plus its `flow` record:

```python
targets = {'asrspoe.com', 'kingoflake.com'}         # replace with your findings
tls_ex = {}; want_flow = {}
for line in open(EVE):
    if '"event_type":"tls"' not in line: continue
    e = json.loads(line)
    if e.get('event_type') != 'tls': continue
    r = registrable((e.get('tls', {}).get('sni') or ''))[1]
    if r in targets and r not in tls_ex:
        tls_ex[r] = e; want_flow[e.get('flow_id')] = r
    if len(tls_ex) == len(targets): break
# second pass over event_type:flow for want_flow keys → age/bytes/state
```
Capture `flow_id`, full `sni`, full `subject`, full `issuerdn`, `ja4`, `version`,
`flow.age`, bytes, pkts, dest IP:port.

---

## Step 7 — Print & save the report

Print the full report to the terminal AND write it to `output_file`.

**CRITICAL — never truncate `tls.sni`, `tls.subject`, or `tls.issuerdn`.**
- `sni` may be a long multi-label DGA name — print every character.
- `subject` / `issuerdn` DN strings must be printed in full (they carry the CN, O, and
  Email that prove self-signed / DGA / IP-CN status). No `[:N]`, no `...`, no ellipsis.
- If a cell is long, let the table row wrap.

```
╔══════════════════════════════════════════════════════════════════════════╗
║   TLS MALICIOUS / C2 HUNT REPORT — Suricata eve.json                      ║
╠══════════════════════════════════════════════════════════════════════════╣
║  File      : /path/to/eve.json                                            ║
║  TLS events: N   (N with SNI)   |   N distinct registrable domains        ║
║  Window    : YYYY-MM-DD  →  YYYY-MM-DD                                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║  VERDICT   : CONFIRMED — [families detected]                              ║
╚══════════════════════════════════════════════════════════════════════════╝

── DNS RESOLVERS / C2 INFRA (dest IPs) ─────────────────────────────────────
  x.x.x.x     description (VPS/hosting, Cloudflare-fronted, mail, …)

── VICTIM IPs (infected internal hosts) ────────────────────────────────────
  x.x.x.x     description  (conns)

── FINDING A — LONG-LIVED FLOWS (flow.age > 5 min) ─────────────────────────
  | reg domain | conns | flows>300s | max flow.age | dest IP(s) | note |

── FINDING B — REPETITIVE BEACONS (many conns, single dest) ────────────────
  | reg domain | conns | dest IPs | window | family |

── FINDING C — IP / INVALID SNI ────────────────────────────────────────────
  | sni | conns | dest | assessment |

── FINDING D — ANOMALOUS CERTIFICATES ──────────────────────────────────────
  malicious (self-signed / IP-CN / DGA-CN / OpenSSL default) vs benign appliances

── FINDING E — SUSPICIOUS-TLD SNI ──────────────────────────────────────────
  by TLD (conns / #domains) + top registrable domains

── JA3 / JA4 PIVOT ─────────────────────────────────────────────────────────
  fingerprint → list of domains it ties together

── EVIDENCE TABLE (TLS ↔ flow) ─────────────────────────────────────────────
| # | src_ip | dest_ip:port | flow_id | tls.sni FULL | subject FULL | issuer FULL | flow.age | bytes(→ ←) | ja4 | note |

── INDICATOR CHECKLIST ─────────────────────────────────────────────────────
  [PASS/FAIL/INFO]  indicator  →  observed value

── OUTPUT FILE ─────────────────────────────────────────────────────────────
  /path/to/tls-hunt-report.txt
```

```python
with open('tls-hunt-report.txt', 'w') as f:
    f.write(report_text)      # same content printed to the terminal
```

---

## Indicator checklist — malicious TLS

| Indicator | Archetype | How to detect |
|---|---|---|
| High-entropy / random-alnum SNI 2LD | Random DGA | `dga_score(label) >= 5` (len, entropy, vowel ratio, digit mix, consonant run) |
| Pronounceable non-dictionary SNI, heavy repeat | Word DGA | low score but `count` high and `ndst == 1` |
| No vowels in SNI 2LD (len ≥ 5) | DGA | vowel ratio == 0 |
| Digit-mixed alphanumeric SNI 2LD | DGA | digit ratio ≥ 0.20 with ≥ 2 digits |
| SNI is an IPv4 / IPv6 literal | IP-SNI | `is_ip(sni)` (violates RFC 6066) |
| SNI ≠ destination host purpose | IP-SNI | IP-SNI while dest is a known mail/CDN IP |
| Malformed SNI (underscore, space, single-label) | Invalid | `invalid_host(sni)`; exclude Akamai `*.akamaihd.net` |
| `sni == localhost` on external TLS | Invalid | exact match |
| SNI in high-abuse TLD | Susp-TLD | `tld_of(sni) in SUSP_TLD` (.xyz/.cc/.cyou/.sbs/.cfd/.top/.online/.icu…) |
| DGA-hex label + cheap TLD | Susp-TLD | e.g. `ca452a2dc910.ga`, `7ab7f6ae8747.tk` |
| Certificate Subject CN is an IP literal | Cert | `is_ip(cn_of(subject))` |
| Certificate Issuer CN is an IP literal | Cert | `is_ip(cn_of(issuerdn))` |
| Invalid cert CN (`0.0.0.0`, private IP) | Cert | value in {0.0.0.0, 127.0.0.1, 192.168.x, 10.x} |
| Self-signed (subject == issuer) | Cert | string equality of subject and issuerdn |
| OpenSSL / default cert template | Cert | `Internet Widgits Pty Ltd`, `Default City`, `Default Company Ltd`, `CN=localhost` |
| Word-DGA CN on junk TLD | Cert | Subject CN 2LD random/word + `tld in SUSP_TLD`; subject==issuer |
| Cert CN in high-abuse TLD | Cert | `tld_of(cn) in SUSP_TLD`; matching subject/issuer counts per TLD |
| flow.age > 5 minutes on suspicious SNI | Long-lived | join `flow_id` → `event_type:flow`, `flow.age > 300` |
| Large byte transfer on a DGA flow | Long-lived | `flow.bytes_toserver/​toclient` on a score≥5 domain |
| Many connections to a single dest IP | Beacon | high `count`, `ndst == 1`, not in `BENIGN` |
| Regular repeated connections over hours/days | Beacon | wide `first→last` window with steady `count` |
| Shared JA3 / JA4 across unrelated domains | Fingerprint | one `ja4` mapping to ≥ 3 registrable domains |
| C2 hosted on cheap VPS / fronted by CDN | Infra | dest IPs on DigitalOcean/OVH/Hetzner, or Cloudflare `172.67.x`/`104.x` |
| No Suricata signature fired | Both | empty / no matching `fast.log` alert for the domain |
| CDN false positive (exclude) | — | high `count` but `ndst` = dozens (Akamai/Azure/Amazon fronts) |
| IoT / appliance false positive (label, don't drop) | — | vendor root CA (Dahua/Hikvision) or ISP CA with private-IP CN |
```
