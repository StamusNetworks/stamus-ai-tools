---
name: hunt-smb-dcerpc
description: "Hunt for malicious SMB / DCERPC activity in Suricata eve.json. Starts from event_type:flow where app_proto is smb or dcerpc and pivots on flow.tx_cnt (high counts = automated abuse), then correlates each flow_id to event_type:smb and event_type:dcerpc records for status codes and RPC interfaces. Detects EternalBlue/MS17-010 SMBv1 exploitation (NT_TRANS access-denied grooming), PsExec-style admin-share (C$) payload writes, credential brute-force / password spray (SESSION_SETUP logon failures), share enumeration, DCSync (DRSUAPI DRSGetNCChanges), NETLOGON abuse (Zerologon-class), RPC coercion (PetitPotam/PrinterBug/DFSCoerce), endpoint-mapper recon, service-control and scheduled-task lateral movement, and SMB2 named-pipe hammering. Surfaces tx_cnt>100 with STATUS_ACCESS_DENIED / STATUS_LOGON_FAILURE. Prints a structured report with an evidence table. Use when asked to hunt SMB/DCERPC/RPC threats, lateral movement, SMB brute-force, EternalBlue, DCSync, or Windows-protocol abuse in a Suricata log."
argument-hint: "[path to eve.json, default: eve.json in current directory] [output file, default: smb-hunt-report.txt alongside eve.json] [tx_cnt threshold, default: 100]"
allowed-tools: "Bash, Read, Write, Glob"
---

# Hunt Malicious SMB / DCERPC in Suricata eve.json

Detect, correlate, and report Windows file-sharing (SMB) and remote-procedure-call
(DCERPC/MSRPC) abuse from a Suricata `eve.json` log. The hunt is **flow-anchored**:
`event_type:flow` gives a per-session `flow.tx_cnt` (number of protocol transactions),
which is the single best cheap signal for "this session did something automated / abusive".
High `tx_cnt` sessions are then joined by `flow_id` to the `event_type:smb` and
`event_type:dcerpc` records, where the **SMB command + status code** and the
**RPC interface UUID + opnum** reveal exactly which technique ran.

Archetypes covered:

| # | Archetype | Primary signal | MITRE ATT&CK |
|---|---|---|---|
| 1 | **EternalBlue / MS17-010** | SMBv1 `NT_TRANS` + `NT_TRANS_SECONDARY`, `status=5` grooming | T1210 Exploit Remote Svc |
| 2 | **PsExec-style lateral move** | `WRITE_ANDX`/`CREATE` to `\\host\C$` (+ SVCCTL) | T1021.002 / T1570 |
| 3 | **Credential brute-force / spray** | many `SESSION_SETUP` → `STATUS_LOGON_FAILURE` | T1110 |
| 4 | **Share enumeration** | `TREE_CONNECT` to `C$`/`ADMIN$`/`SYSVOL`/`IPC$`, `ACCESS_DENIED` | T1135 |
| 5 | **DCSync** | DCERPC **DRSUAPI** `DRSGetNCChanges` (opnum 3) | T1003.006 |
| 6 | **Zerologon / NETLOGON abuse** | hundreds–thousands of **NETLOGON** requests in one flow | T1210 / CVE-2020-1472 |
| 7 | **RPC coercion** | **EFSR**/**MS-RPRN**/**DFSNM**/**FSRVP** binds (PetitPotam/PrinterBug) | T1187 Forced Auth |
| 8 | **Endpoint-mapper recon** | **EPM** `ept_map` on `:135` before a dynamic-port RPC | T1046 |
| 9 | **Service / task exec** | **SVCCTL**, **ATSVC/TSCH** binds + create calls | T1543.003 / T1053.005 |
| 10 | **Named-pipe hammering** | SMB2 `IOCTL`+`CREATE`+`CLOSE` loops, `tx_cnt` in the thousands | recon / coercion |

## Arguments

- `eve_path` — Path to `eve.json` (default: `eve.json` in working directory)
- `output_file` — Report path (default: `smb-hunt-report.txt` next to `eve.json`)
- `tx_threshold` — `flow.tx_cnt` cutoff for "high" (default: `100`)

---

## Step 1 — Locate, size, and confirm the schema

```bash
wc -l eve.json
grep '"event_type":"flow"' eve.json | grep -oE '"app_proto":"(smb|dcerpc)"' | sort | uniq -c
grep -c '"event_type":"smb"'    eve.json
grep -c '"event_type":"dcerpc"' eve.json
grep -m1 '"event_type":"flow"' eve.json | grep '"app_proto":"smb"' | python3 -m json.tool | head -40
grep -m1 '"event_type":"smb"'    eve.json | python3 -m json.tool
grep -m1 '"event_type":"dcerpc"' eve.json | python3 -m json.tool
```

**Field reference**

Field lists below are the full set observed in Suricata SMB/DCERPC output. Any field may
be absent on a given record (it depends on the command, the dialect, and whether NTLM/
Kerberos/DCERPC-over-pipe was used in that transaction).

### Top-level fields (present on smb / dcerpc / alert records alike)
`timestamp`, `flow_id` (**join key** to `event_type:flow`), `pcap_cnt`, `event_type`,
`src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `ip_v`, `pkt_src`, `tx_id`
(SMB records only), and `app_proto` (on flow/alert; implied on smb/dcerpc records —
report as `"smb"` / `"dcerpc"`).

### `event_type:flow` (the anchor)
- `app_proto` — `"smb"` or `"dcerpc"` (`"krb5"` / `"ntlm"` may accompany on the same host).
- `flow.tx_cnt` — **transactions in the session** — the primary hunt pivot.
- `flow.pkts_toserver` / `flow.pkts_toclient`, `flow.bytes_toserver` / `flow.bytes_toclient`.
- `flow.start`, `flow.end`, `flow.age`, `flow.state`, `flow.reason`, `flow.alerted`.

### `event_type:smb` — `smb.*`
Core / session:
- `smb.id` — internal SMB transaction id.
- `smb.command` — e.g. `SMB2_COMMAND_TREE_CONNECT`, `SMB1_COMMAND_NT_TRANS`,
  `SMB2_COMMAND_IOCTL`, `SMB2_COMMAND_CREATE`/`CLOSE`/`WRITE`/`READ`/`SESSION_SETUP`.
- `smb.status` / `smb.status_code` — **key field**: `STATUS_SUCCESS`, `STATUS_ACCESS_DENIED`,
  `STATUS_LOGON_FAILURE`, `STATUS_BAD_NETWORK_NAME`, or raw `"5"` (Win32 `ERROR_ACCESS_DENIED`).
- `smb.session_id`, `smb.tree_id`.

Negotiation / capabilities:
- `smb.dialect` (e.g. `NT LM 0.12`, `2.10`, `3.11`), `smb.client_dialects[]`.
- `smb.client_guid`, `smb.server_guid`, `smb.max_read_size`, `smb.max_write_size`.

Tree / share / pipe:
- `smb.share` — e.g. `\\host\C$`, `\\host\SYSVOL`, `\\host\IPC$`.
- `smb.share_type` — `FILE`, `PIPE`, `PRINT`.
- `smb.named_pipe` — pipe name (e.g. `\srvsvc`, `\lsarpc`, `\samr`, `\netlogon`).
- `smb.service.request` / `smb.service.response`, `smb.function`.

File operations:
- `smb.filename`, `smb.fuid`, `smb.directory`, `smb.disposition`, `smb.access`, `smb.size`.
- `smb.created`, `smb.accessed`, `smb.modified`, `smb.changed` (timestamps).

Authentication identity (**attacker attribution**):
- `smb.ntlmssp.user`, `smb.ntlmssp.domain`, `smb.ntlmssp.host`, `smb.ntlmssp.version`.
- `smb.request.native_os` / `smb.request.native_lm`, `smb.response.native_os` / `.native_lm`.
- `smb.kerberos.realm`, `smb.kerberos.snames[]` (SPNs requested).

Embedded DCERPC (RPC-over-SMB **named pipe** — RPC carried inside SMB, not on a TCP port):
- `smb.dcerpc.request` / `smb.dcerpc.response`, `smb.dcerpc.call_id`, `smb.dcerpc.opnum`.
- `smb.dcerpc.interfaces[].{uuid,version,ack_result,ack_reason}` — **bound RPC interface** (see UUID map).
- `smb.dcerpc.req.{frag_cnt,stub_data_size}`, `smb.dcerpc.res.{frag_cnt,stub_data_size}`.
  > Attacks like DCSync, SAMR/LSARPC enum, SVCCTL and the coercion RPCs frequently ride
  > over the named pipe — so **also inspect `smb.dcerpc.interfaces[].uuid`**, not only the
  > standalone `event_type:dcerpc` records.

### `event_type:dcerpc` — `dcerpc.*` (RPC over its own TCP port, e.g. :135 or 49xxx)
- `dcerpc.request` — `BIND`, `ALTER_CONTEXT`, `REQUEST`; `dcerpc.response` — `BINDACK`, `RESPONSE`, `FAULT`.
- `dcerpc.interfaces[].{uuid, version, ack_result}` — **the bound RPC interface UUID** (see map below);
  `ack_result` `0`=accept, `2`=provider-rejection, `3`=negotiate-ack.
- `dcerpc.req.{opnum, frag_cnt, stub_data_size}` — **`opnum` pinpoints the exact call** (e.g. DRSUAPI opnum 3 = DCSync).
- `dcerpc.res.{frag_cnt, stub_data_size}`.
- `dcerpc.call_id`, `dcerpc.rpc_version`.

### `event_type:alert` where `app_proto` is `smb` or `dcerpc`
> **Not present in this capture** — it has 0 alert events (`fast.log` is empty; the sensor
> ran without rules loaded). Schema documented here for completeness / other datasets.

When a rule fires on an SMB/DCERPC flow, Suricata emits an `alert` record that carries the
signature **plus the app-layer metadata** for the transaction:
- `alert.action` (`allowed`/`blocked`), `alert.gid`, `alert.signature_id`, `alert.rev`,
  `alert.signature` (rule msg), `alert.category`, `alert.severity`, `alert.metadata{}`
  (rule metadata: `mitre_technique_id`, `cve`, etc. when set), and — if configured —
  `alert.source` / `alert.target`.
- `app_proto` — `"smb"` or `"dcerpc"` (top-level on the alert).
- The **same `smb{}` or `dcerpc{}` metadata sub-object** described above (the command/status
  or interface/opnum that the alert triggered on), plus `tx_id`.
- The `flow{}` object when `eve-log → alert → metadata`/`flow` is enabled (gives `flow.tx_cnt`,
  bytes, age at alert time — the same pivots used elsewhere in this skill).
- Correlate an alert back to the full session with `flow_id`, exactly as with smb/dcerpc records.

---

## Step 2 — SMB status codes that matter

Access-denied appears in **three** forms — match all of them:

```python
DENIED = {'STATUS_ACCESS_DENIED', '5', 'STATUS_LOGON_FAILURE',
          'STATUS_ACCOUNT_DISABLED', 'STATUS_ACCOUNT_LOCKED_OUT',
          'STATUS_PASSWORD_EXPIRED', 'STATUS_WRONG_PASSWORD',
          'SRV_BADUID', 'STATUS_NETWORK_SESSION_EXPIRED'}
```
- `"5"` = Win32 `ERROR_ACCESS_DENIED` (Suricata emits the bare numeric for some SMB1/DCERPC paths).
- `STATUS_ACCESS_DENIED` (`0xC0000022`) — share/object access refused.
- `STATUS_LOGON_FAILURE` (`0xC000006D`) — **authentication failed** → brute-force / spray.

Other high-value statuses: `STATUS_BAD_NETWORK_NAME` (probing non-existent shares),
`STATUS_ACCOUNT_LOCKED_OUT` (spray tripped lockout), `STATUS_MORE_PROCESSING_REQUIRED`
(normal NTLM handshake continuation — not an error).

---

## Step 3 — DCERPC interface UUID → attack map

The **interface UUID** in `dcerpc.interfaces[].uuid` tells you what an RPC session is for.
Keep this map; it converts opaque binds into named techniques.

| UUID | Interface | Abuse / tooling |
|---|---|---|
| `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | **DRSUAPI** (MS-DRSR) | **DCSync** — opnum 3 `DRSGetNCChanges` dumps secrets |
| `12345678-1234-abcd-ef00-01234567cffb` | **NETLOGON** (MS-NRPC) | **Zerologon** (CVE-2020-1472); opnum 26 `NetrServerAuthenticate3`, 30 `NetrServerPasswordSet2` |
| `12345778-1234-abcd-ef00-0123456789ab` | **LSARPC** (MS-LSAD) | LSA policy / secrets / SID lookups (recon) |
| `12345778-1234-abcd-ef00-0123456789ac` | **SAMR** (MS-SAMR) | user / group / RID enumeration |
| `12345678-1234-abcd-ef00-0123456789ab` | **MS-RPRN** (spoolss) | **PrinterBug** coercion; **PrintNightmare** (opnum `RpcAddPrinterDriverEx`) |
| `76f03f96-cdfd-44fc-a22c-64950a001209` | **MS-PAR** (print async) | PrintNightmare variant |
| `c681d488-d850-11d0-8c52-00c04fd90f7e` | **MS-EFSR** (EFSRPC) | **PetitPotam** forced auth (`EfsRpcOpenFileRaw`, opnum 0) |
| `df1941c5-fe89-4e79-bf10-463657acf44d` | **MS-EFSR** (alt binding) | PetitPotam variant |
| `4fc742e0-4a10-11cf-8273-00aa004ae673` | **MS-DFSNM** | **DFSCoerce** forced auth |
| `a8e0653c-2744-4389-a61d-7373df8b2292` | **MS-FSRVP** | **ShadowCoerce** forced auth |
| `367abb81-9844-35f1-ad32-98f038001003` | **SVCCTL** (MS-SCMR) | remote **service** create/start → PsExec-style exec |
| `86d35949-83c9-4044-b424-db363231fd0c` | **ATSVC / ITaskSchedulerService** | **scheduled task** lateral movement |
| `338cd001-2244-31f1-aaaa-900038001003` | **WINREG** (MS-RRP) | remote registry (recon / persistence) |
| `4b324fc8-1670-01d3-1278-5a47bf6ee188` | **SRVSVC** | `NetShareEnum` share enumeration |
| `6bffd098-a112-3610-9833-46c3f87e345a` | **WKSSVC** | workstation enum |
| `8bc3f05e-d86b-11d0-a075-00c04fb68820` | **IWbemLevel1Login** (WMI) | WMI remote exec (T1047) |
| `e1af8308-5d1f-11c9-91a4-08002b14a0fa` | **EPM** (endpoint mapper) | `ept_map` recon on `:135` — resolves the above to dynamic ports |

```python
RPC_IFACE = {
 'e3514235-4b06-11d1-ab04-00c04fc2dcd2':'DRSUAPI (DCSync)',
 '12345678-1234-abcd-ef00-01234567cffb':'NETLOGON (Zerologon)',
 '12345778-1234-abcd-ef00-0123456789ab':'LSARPC',
 '12345778-1234-abcd-ef00-0123456789ac':'SAMR',
 '12345678-1234-abcd-ef00-0123456789ab':'MS-RPRN spoolss (PrinterBug/PrintNightmare)',
 '76f03f96-cdfd-44fc-a22c-64950a001209':'MS-PAR (PrintNightmare)',
 'c681d488-d850-11d0-8c52-00c04fd90f7e':'MS-EFSR (PetitPotam)',
 'df1941c5-fe89-4e79-bf10-463657acf44d':'MS-EFSR (PetitPotam)',
 '4fc742e0-4a10-11cf-8273-00aa004ae673':'MS-DFSNM (DFSCoerce)',
 'a8e0653c-2744-4389-a61d-7373df8b2292':'MS-FSRVP (ShadowCoerce)',
 '367abb81-9844-35f1-ad32-98f038001003':'SVCCTL (service exec)',
 '86d35949-83c9-4044-b424-db363231fd0c':'ATSVC/TSCH (scheduled task)',
 '338cd001-2244-31f1-aaaa-900038001003':'WINREG (remote registry)',
 '4b324fc8-1670-01d3-1278-5a47bf6ee188':'SRVSVC (share enum)',
 '6bffd098-a112-3610-9833-46c3f87e345a':'WKSSVC',
 '8bc3f05e-d86b-11d0-a075-00c04fb68820':'WMI (remote exec)',
 'e1af8308-5d1f-11c9-91a4-08002b14a0fa':'EPM (endpoint mapper recon)'}
```

---

## Step 4 — First pass: tx_cnt distribution + high-tx flow set

Anchor on `event_type:flow`. Pre-filter lines with grep before `json.loads`.

```python
import json, collections
EVE = 'eve.json'; TX = 100

dist = collections.Counter(); tot = collections.Counter()
high = {}   # flow_id -> flow facts (tx_cnt > TX)
for line in open(EVE):
    if '"event_type":"flow"' not in line: continue
    if '"smb"' not in line and '"dcerpc"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'flow': continue
    ap = e.get('app_proto', '')
    if ap not in ('smb', 'dcerpc'): continue
    f = e.get('flow', {}); tx = f.get('tx_cnt')
    tot[ap] += 1
    if tx is None: continue
    b = ('>1000' if tx > 1000 else '501-1000' if tx > 500 else '101-500' if tx > 100
         else '51-100' if tx > 50 else '11-50' if tx > 10 else '1-10')
    dist[b] += 1
    if tx > TX:
        high[e['flow_id']] = {'ap': ap, 'tx': tx, 'src': e.get('src_ip'), 'dst': e.get('dest_ip'),
            'dport': e.get('dest_port'), 'bts': f.get('bytes_toserver'), 'btc': f.get('bytes_toclient'),
            'pts': f.get('pkts_toserver'), 'ptc': f.get('pkts_toclient'),
            'age': f.get('age'), 'state': f.get('state')}

print("smb/dcerpc flows:", dict(tot))
for b in ['1-10','11-50','51-100','101-500','501-1000','>1000']:
    print(f"  {b:>9}: {dist[b]}")
print("high-tx flows (>%d): %d" % (TX, len(high)))
```

**Red flags:** any bucket in `>1000`; a cluster of **identical** `tx_cnt` values across many
src→dst pairs (an automated tool run repeatedly — e.g. the `tx=120` EternalBlue signature).

---

## Step 5 — Correlate high-tx flows to SMB records

```python
DENIED = {'STATUS_ACCESS_DENIED','5','STATUS_LOGON_FAILURE','STATUS_ACCOUNT_DISABLED',
          'STATUS_ACCOUNT_LOCKED_OUT','STATUS_PASSWORD_EXPIRED','STATUS_WRONG_PASSWORD',
          'SRV_BADUID','STATUS_NETWORK_SESSION_EXPIRED'}
ADMIN_SHARES = ('C$','ADMIN$','IPC$','SYSVOL','NETLOGON')

agg = collections.defaultdict(lambda: {'n':0,'denied':0,'status':collections.Counter(),
     'cmd':collections.Counter(),'shares':collections.Counter(),'files':collections.Counter(),
     'users':collections.Counter(),'domains':collections.Counter(),'hosts':collections.Counter(),
     'dialect':collections.Counter()})
for line in open(EVE):
    if '"event_type":"smb"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'smb' or e.get('flow_id') not in high: continue
    s = e.get('smb', {}); a = agg[e['flow_id']]; a['n'] += 1
    st = str(s.get('status',''))
    a['status'][st] += 1; a['cmd'][s.get('command','')] += 1
    if st in DENIED: a['denied'] += 1
    if s.get('share'):    a['shares'][s['share']] += 1
    if s.get('filename'): a['files'][s['filename']] += 1
    if s.get('dialect'):  a['dialect'][s['dialect']] += 1
    n = s.get('ntlmssp')
    if isinstance(n, dict):
        for k in ('user','domain','host'):
            if n.get(k): a[{'user':'users','domain':'domains','host':'hosts'}[k]][n[k]] += 1

# rank SMB flows by access-denied then tx_cnt
smb_rows = sorted(((high[f], agg[f], f) for f in high if high[f]['ap']=='smb'),
                  key=lambda r: (-r[1]['denied'], -r[0]['tx']))
for info, a, fid in smb_rows[:40]:
    print(f"{info['src']:15}->{info['dst']:15}:{info['dport']} tx={info['tx']:>5} "
          f"denied={a['denied']:>4} cmds={a['cmd'].most_common(3)} shares={a['shares'].most_common(2)} "
          f"user={a['users'].most_common(1)}")
```

### 5a — EternalBlue / MS17-010 signature
SMBv1 `SMB1_COMMAND_NT_TRANS` with `status=5`, interleaved with `NT_TRANS_SECONDARY`
(fragmented transactions), plus `NT_CREATE_ANDX`/`TREE_DISCONNECT` access-denied.
The **repetition of an identical `tx_cnt`** (e.g. exactly 120) across many src→dst pairs =
automated worm/scanner. Confirm by dumping one flow's `(command,status)` histogram.

### 5b — PsExec-style lateral movement
`WRITE_ANDX` / `SMB2_COMMAND_WRITE` / `CREATE` to `\\host\C$` or `ADMIN$`, often with
`ntlmssp.user`/`domain` populated (captured credential). Pair with a DCERPC **SVCCTL** bind
(service create) on the same host to confirm remote execution.

### 5c — Brute-force / password spray
Many `SESSION_SETUP` (SMB1 `SESSION_SETUP_ANDX` / SMB2 `SESSION_SETUP`) →
`STATUS_LOGON_FAILURE`. Aggregate by src→dst; a fan-out of one src to many dst = spray,
many attempts one dst = brute-force. Watch for `STATUS_ACCOUNT_LOCKED_OUT`.

### 5d — Share enumeration
`TREE_CONNECT` to admin/DC shares (`C$`,`ADMIN$`,`IPC$`,`SYSVOL`,`NETLOGON`) with
`ACCESS_DENIED`; `SYSVOL`/`NETLOGON` targets identify a **domain controller**.

---

## Step 6 — Correlate high-tx flows to DCERPC records

```python
rpc = collections.defaultdict(lambda: {'n':0,'ifaces':collections.Counter(),
      'opnums':collections.Counter(),'reqtypes':collections.Counter()})
for line in open(EVE):
    if '"event_type":"dcerpc"' not in line: continue
    try: e = json.loads(line)
    except: continue
    if e.get('event_type') != 'dcerpc' or e.get('flow_id') not in high: continue
    d = e.get('dcerpc', {}); r = rpc[e['flow_id']]; r['n'] += 1
    r['reqtypes'][d.get('request') or d.get('response') or ''] += 1
    for i in (d.get('interfaces') or []):
        u = (i.get('uuid') or '').lower()
        r['ifaces'][RPC_IFACE.get(u, u)] += 1
    op = (d.get('req') or {}).get('opnum')
    if op is not None: r['opnums'][op] += 1

for info, a in sorted(((high[f], rpc[f]) for f in high if high[f]['ap']=='dcerpc'),
                      key=lambda r: -r[0]['tx']):
    named = [x for x in a['ifaces'] if not x.count('-') == 4]     # resolved names first
    print(f"{info['src']:15}->{info['dst']:15}:{info['dport']} tx={info['tx']:>5} rpc_ev={a['n']} "
          f"ifaces={a['ifaces'].most_common(3)} opnums={a['opnums'].most_common(4)}")
```

Flag: **DRSUAPI + opnum 3** (DCSync), hundreds of **NETLOGON** requests (Zerologon),
any **EFSR/MS-RPRN/DFSNM/FSRVP** bind (coercion), **SVCCTL**/**ATSVC** (exec),
**EPM** on `:135` immediately preceding a dynamic-port bind (recon → attack chain).

> Note: `dcerpc.interfaces` is populated on `BIND`/`BINDACK`; on `REQUEST` records the
> opnum lives in `dcerpc.req.opnum`. `flow.tx_cnt` counts *all* transactions, so it can
> exceed the number of logged `dcerpc` events (Suricata may not emit one per transaction).

---

## Step 7 — Pull evidence rows for the report

For each headline finding grab the `flow_id` and one representative record:

```python
# resolve a flow_id by (src,dst) among high-tx flows, then dump its (command,status) or (iface,opnum)
def flow_for(src, dst):
    return next((f for f in high if high[f]['src']==src and high[f]['dst']==dst), None)
```
Capture: `flow_id`, `app_proto`, `src→dst:port`, `flow.tx_cnt`, bytes(→ ←), `flow.age`,
denied count, and the signature (SMB command/status histogram or RPC interface/opnum).

---

## Step 8 — Print & save the report

Print to the terminal AND write to `output_file`. Do **not** truncate share paths,
filenames, NTLMSSP identities, or interface UUIDs — they are the evidence.

```
╔══════════════════════════════════════════════════════════════════════════╗
║   SMB / DCERPC HUNT REPORT — high tx_cnt + Access-Denied — eve.json        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  File   : /path/to/eve.json                                               ║
║  Scope  : event_type:flow app_proto∈{smb,dcerpc}; flow.tx_cnt > N          ║
║  Volume : N smb flows | N dcerpc flows | N smb records | N dcerpc records  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  VERDICT: [CONFIRMED / SUSPICIOUS] — [techniques]                          ║
╚══════════════════════════════════════════════════════════════════════════╝

── flow.tx_cnt DISTRIBUTION ────────────────────────────────────────────────
  1-10 | 11-50 | 51-100 | 101-500 | 501-1000 | >1000

── ATTACKERS → TARGETS (by total access-denied on high-tx flows) ───────────
  app_proto  src -> dst   denied  Σtx  flows

── FINDING 1..N (one per detected archetype) ───────────────────────────────
  signature, endpoints, shares/files, captured credentials, RPC interface+opnum

── EVIDENCE TABLE ──────────────────────────────────────────────────────────
| # | app_proto | src → dest:port | flow_id | flow.tx_cnt | bytes(→ ←) | age | denied | signature |

── CAPTURED CREDENTIALS / IDENTITIES (NTLMSSP) ─────────────────────────────
  user / domain / host observed on session setup

── INDICATOR CHECKLIST ─────────────────────────────────────────────────────
  [PASS/FAIL/INFO]  indicator  →  observed value

── OUTPUT FILE ─────────────────────────────────────────────────────────────
  /path/to/smb-hunt-report.txt
```

```python
with open('smb-hunt-report.txt', 'w') as f:
    f.write(report_text)
```

---

## Indicator checklist — malicious SMB / DCERPC

| Indicator | Archetype | How to detect |
|---|---|---|
| `flow.tx_cnt > 100` on smb/dcerpc flow | All | Step 4 distribution + high set |
| Identical high `tx_cnt` repeated across src→dst pairs | Worm/scanner | group high flows by `tx_cnt` value + count distinct pairs |
| Access-denied concentration on a flow | All | `status ∈ DENIED` count per `flow_id` (incl. raw `"5"`) |
| SMBv1 `NT_TRANS` + `NT_TRANS_SECONDARY` with `status=5` | EternalBlue | per-flow `(command,status)` histogram |
| SMBv1 in use at all on `:445` | Exposure/exploit | `dialect == "NT LM 0.12"` / `SMB1_COMMAND_*` |
| `WRITE_ANDX`/`CREATE` to `\\host\C$` or `ADMIN$` | Lateral move | `smb.share` endswith admin share + write command |
| Many `SESSION_SETUP` → `STATUS_LOGON_FAILURE` | Brute-force/spray | count per src→dst; fan-out = spray |
| `STATUS_ACCOUNT_LOCKED_OUT` observed | Spray fallout | status match |
| `TREE_CONNECT` to `SYSVOL`/`NETLOGON` (DC shares) | Recon | share name → target is a DC |
| DCERPC **DRSUAPI** bind + opnum 3 (`DRSGetNCChanges`) | DCSync | UUID `e3514235…` + `req.opnum == 3` |
| Hundreds–thousands of **NETLOGON** requests in one flow | Zerologon | UUID `12345678…cffb`, high `tx_cnt`/req count |
| DCERPC **EFSR/MS-RPRN/DFSNM/FSRVP** bind | Coercion | UUID in coercion set (PetitPotam/PrinterBug/DFSCoerce) |
| DCERPC **SVCCTL** bind + create | Service exec | UUID `367abb81…` |
| DCERPC **ATSVC/TSCH** bind | Scheduled task | UUID `86d35949…` |
| DCERPC **SAMR/LSARPC** heavy enum | Recon | UUID `12345778…ac`/`…ab` with many requests |
| **EPM** `ept_map` on `:135` before dynamic-port RPC | Recon chain | UUID `e1af8308…` then same src→dst on 49xxx |
| SMB2 `IOCTL`+`CREATE`+`CLOSE` loop, `tx_cnt` in thousands | Pipe hammering | command histogram dominated by these three |
| Captured NTLMSSP `user`/`domain`/`host` | Attribution | `smb.ntlmssp.*` on session setup |
| Outbound SMB (`:445`) to a public IP | Exfil / rogue server | `dest_ip` not RFC1918 on high-tx smb flow |
| No Suricata signature fired | All | empty/absent matching `fast.log` alert |
| High tx but `state != established` / short `age` | Scan | flow closed fast with many tx = probing |
```
