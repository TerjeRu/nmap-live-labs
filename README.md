# █▓▒▒░░░ NMAP NETWORK‑SCANNING TUTORIAL ░░░▒▒▓█

Purpose: Deliver an end‑to‑end, lab‑driven curriculum that not only shows how to operate Nmap but digs into the why behind every flag, packet, and log entry. The guide scales from a two‑VM sandbox to a small enterprise test range and includes blue‑team instrumentation so defenders can follow along.

Read‑Me First:

```
Running time: 8–12 hours for the core path; ~20 hours with every extension.
Prerequisites: Basic Linux CLI navigation; virtualization software; isolated lab network (Host‑Only or equivalent).
Safety: Perform all activities on isolated networks only. Port‑scanning random hosts can trigger legal and policy violations.
```

---

零 – ENVIRONMENT PREPARATION

Establish a hermetically sealed playground where traffic is confined to the host‑only network and every required tool is installed. Misconfigured adapters are the #1 cause of “Why is nothing responding?” panic on day one.

► CONCEPT BRIEF — Why Host‑Only?

```
Bridged adapters leak scans to your corporate LAN. NAT hides your target from the attacker VM. Host‑Only strikes a Goldilocks balance: isolation plus full Layer‑2 visibility (ARP works out of the box).
```

► PRE‑LAB CHECKLIST

```
Snapshots: Take VM snapshots now; it’s your instant rewind button.
USB Wi‑Fi (Optional): If you plan wireless tests, pass through a compatible adapter.
```

► STEP‑BY‑STEP

| # | Action             | Command                                                                       | Look For             | Why It Matters                             |
| - | ------------------ | ----------------------------------------------------------------------------- | -------------------- | ------------------------------------------ |
| 1 | Configure adapters | Hypervisor UI                                                                 | Host‑Only on each VM | Guarantees isolation                       |
| 2 | Verify Layer‑2     | `arping ‑I eth0 192.168.56.102`                                               | Single MAC reply     | Confirms link‑level connectivity           |
| 3 | Verify Layer‑3     | `ping ‑c3 192.168.56.102`                                                     | <1 ms latency        | Confirms IP routing and basic reachability |
| 4 | Install toolchain  | `sudo apt update && sudo apt install ‑y nmap wireshark tshark ndiff xsltproc` | `nmap 7.95+`         | Ensures up‑to‑date scanning and reporting  |

Expected Outcome:

```
• Both VMs respond to ping and ARP; logs show no other traffic.
• `nmap --version` prints 7.95 or newer, with Lua 5.4 support.
```

Troubleshooting:

```
If `Destination Host Unreachable` appears, re‑check adapter type and reboot VMs.
If packet loss exceeds 1%, enable promiscuous mode on host‑only interface.
```

---

壱 – LAB 1: HOST DISCOVERY

Identify which IPs are alive before blasting ports—think of discovery as ringing doorbells.

► CONCEPT BRIEF — Discovery Methods

```
ARP: Local LAN only; best for on‑subnet hosts.
ICMP: Works across routers but often blocked.
TCP Ping (`-PS`): Sends SYNs to specified ports; may bypass ICMP filters.
Skip (`-Pn`): Forces scanning without discovery; wastes time on dead hosts if used indiscriminately.
```

► PRE‑LAB CHECKLIST

```
Start Wireshark on `eth0`; save any previous captures.
Create working dir: `mkdir ‑p ~/nmap‑labs/lab1 && cd ~/nmap‑labs/lab1`.
```

► STEP‑BY‑STEP

| Task                | Command                                                   | Observe in Wireshark            |
| ------------------- | --------------------------------------------------------- | ------------------------------- |
| ARP Sweep           | `sudo nmap ‑sn 192.168.56.0/24 ‑oN arp_sweep.txt`         | ARP who‑has broadcasts, replies |
| TCP SYN Ping        | `sudo nmap ‑sn ‑PS80,443 192.168.56.102 ‑oN syn_ping.txt` | SYN→RST pairs                   |
| ICMP Echo & TS Ping | `sudo nmap ‑sn ‑PE ‑PP 192.168.56.0/24 ‑oN icmp.txt`      | ICMP Echo/TimeStamp requests    |
| No Discovery        | `sudo nmap ‑sn ‑Pn 192.168.56.102 ‑oN skip.txt`           | Zero discovery packets          |

Expected Outcome:

```
• ARP completes in <2 s, listing all live hosts.
• SYN ping shows timely handshakes or resets.
• `-Pn` produces no outbound probes.
```

Troubleshooting:

```
If hosts go missing, ensure both VMs share the same vNIC type (e.g., Intel E1000).
```

Reflection:

```
In two sentences, justify when `-Pn` is appropriate and outline its trade‑offs.
```

---

弐 – LAB 2: TCP SCANNING FUNDAMENTALS

Probe open ports using Connect (`-sT`) or SYN (`-sS`) scans. Connect scans complete handshakes (unprivileged) and generate full logs; SYN scans (root) send half‑open SYNs, offering stealth and efficiency.

► PRE‑LAB CHECKLIST

```
Confirm Lab 1 live-host list.
Restart Wireshark; clear previous captures.
```

► STEP‑BY‑STEP

| Task                  | Command                                                                 | Observe                    |
| --------------------- | ----------------------------------------------------------------------- | -------------------------- |
| Connect Scan          | `nmap -sT -p1-1024 192.168.56.102 -oN lab2_connect.txt`                 | Full 3‑way handshakes      |
| SYN Scan              | `sudo nmap -sS -p1-1024 192.168.56.102 -oN lab2_syn.txt`                | SYN→RST lifecycle          |
| FIN/NULL/XMAS Scans   | `sudo nmap -sF -sN -sX -p1-1024 192.168.56.102 -oN lab2_weird.txt`      | Silence = filtered or open |
| Idle Scan (Extension) | `sudo nmap -sI 192.168.56.103 192.168.56.102 -p22,80 -oN lab2_idle.txt` | Appears from zombie host   |

Expected Outcome:

```
• SYN scan uses ~50% fewer packets than Connect.
• FIN/NULL/XMAS scans show many ports as filtered due to silence.
```

Troubleshooting:

```
If SYN scan errors: disable NIC offloading or use `sudo`.
```

Reflection:

```
Which scan balances stealth and access privileges? (Answer: SYN scan.)
```

---

参 – LAB 3: UDP SCANNING BASICS

UDP ports lack feedback; Nmap infers openness by absence of ICMP unreachable messages. Patience and tuning retries/timeouts are key.

► PRE‑LAB CHECKLIST

```
Verify host up via ICMP.
Note open TCP ports from Lab 2.
```

► STEP‑BY‑STEP

| Task                      | Command                                                                                           | Notes                            |          |
| ------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------- | -------- |
| Top‑20 UDP Ports          | `sudo nmap -sU --top-ports 20 192.168.56.102 -oN lab3_top20.txt`                                  | Slow: each port probes timeout   |          |
| SNMP Info                 | `sudo nmap -sU -p161 --script snmp-info 192.168.56.102 -oN lab3_snmp.txt`                         | Dumps community/mib details      |          |
| Fast UDP (Retries=2)      | `sudo nmap -sU --top-ports 50 --max-retries 2 --host-timeout 2m 192.168.56.102 -oN lab3_fast.txt` | Trade-offs open                  | filtered |
| Fragmentation (Extension) | `sudo nmap -sU -f --top-ports 20 192.168.56.102 -oN lab3_frag.txt`                                | Tests firewall reassembly quirks |          |

Expected Outcome:

```
• SNMP port (161) returns open with device info.
• Fragmented probes may slip past ACLs.
```

Troubleshooting:

```
If every port shows open|filtered: remove timeouts or add retries.
```

Reflection:

```
How can dropping ICMP unreachable help detect UDP scans? 
```

---

肆 – LAB 4: SERVICE & OS DETECTION

Fingerprint services (`-sV`) and OS (`-O`) by sending specific probes and analyzing protocol quirks.

► PRE‑LAB CHECKLIST

```
Have open ports list (Labs 2 & 3).
```

► STEP‑BY‑STEP

| Task            | Command                                                                           | Observe                           |
| --------------- | --------------------------------------------------------------------------------- | --------------------------------- |
| Version Scan    | `sudo nmap -sV -p21,22,80,139,445 --version-all 192.168.56.102 -oN lab4_vers.txt` | Detailed banner probes            |
| OS Detection    | `sudo nmap -O --osscan-guess 192.168.56.102 -oN lab4_os.txt`                      | TTL, TCP options quirks           |
| Aggressive Mode | `sudo nmap -A -T4 192.168.56.102 -oN lab4_aggr.txt`                               | Combined -sV, -O, NSE, traceroute |

Expected Outcome:

```
• Accurate services: vsftpd2.3.4, Apache2.2.8.
• OS guess: Linux kernel 2.6.x.
```

Troubleshooting:

```
If OS detection fails: add `--osscan-limit` or increase intensity.
```

Reflection:

```
Why is full 65k port version scanning a rookie mistake? 
```

---

伍 – LAB 5: TIMING & PERFORMANCE TUNING

Adjust timing templates (`-T0`–`-T5`), rate limits, and timeouts to balance speed and detection risk.

► PRE‑LAB CHECKLIST

```
Baseline scan: `sudo nmap -sS -p1-1000 192.168.56.102 -oN lab5_base.txt`.
```

► STEP‑BY‑STEP

| Task                  | Command                                                                                            | Observe                         |
| --------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------- |
| Template Comparison   | `for T in 2 3 4 5; do sudo nmap -sS -p1-1000 -T$T 192.168.56.102 -oN lab5_T$T.txt; done`           | Runtime vs misses               |
| Rate Limiting         | `sudo nmap -sS -p1-1000 --min-rate20 --max-rate50 --max-retries1 192.168.56.102 -oN lab5_rate.txt` | Packet spread vs duration       |
| Host Timeout          | `sudo nmap -sS -p- --host-timeout5m 192.168.56.102 -oN lab5_fullfast.txt`                          | Complete scan within SLA        |
| Adaptive Timing (Ext) | `sudo nmap -sS -p1-1000 --adaptive --max-parallelism50 192.168.56.102 -oN lab5_adapt.txt`          | Auto-throttle under packet loss |

Expected Outcome:

```
• `-T5` ~3× faster than `-T3` but misses ~5% under 10% loss.
```

Troubleshooting:

```
If fast templates hang: disable offloading or `--defeat-rst-ratelimit`.
```

Reflection:

```
Name a scenario where stealth outweighs speed.
```

---

陸 – LAB 6: FIREWALL / IDS EVASION

Use fragmentation, decoys, source-port spoofing, and padding to alter packet signatures and delay detection.

► STEP‑BY‑STEP

| Technique      | Command                                                                            | Purpose                   |
| -------------- | ---------------------------------------------------------------------------------- | ------------------------- |
| Baseline       | `sudo nmap -sS -p445 192.168.56.102 -oN lab6_base.txt`                             | Control comparison        |
| Fragmentation  | `sudo nmap -sS -f -p445 192.168.56.102 -oN lab6_frag.txt`                          | Bypass simple reassembly  |
| Decoys         | `sudo nmap -sS -D RND:5 -p445 192.168.56.102 -oN lab6_decoy.txt`                   | Mix fake sources          |
| Source Port 53 | `sudo nmap -sS --source-port53 -p445 192.168.56.102 -oN lab6_sport.txt`            | Mimic DNS                 |
| Data Padding   | `sudo nmap -sS --data-length60 --spoof-mac0 -p445 192.168.56.102 -oN lab6_pad.txt` | Alter payload fingerprint |

Expected Outcome:

```
• Port 445 still open; combined evasion yields fewer IDS alerts.
```

Troubleshooting:

```
If decoys stall: add `--max-scan-delay20ms`.
```

Reflection:

```
Which technique best delayed detection? Why?
```

---

漆 – LAB 7: NSE (SCRIPTING ENGINE)

Automate scans and vulnerability checks with Lua scripts categorized by safety and risk.

► STEP‑BY‑STEP

| Task                | Command                                                                                                                                     | Notes                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Default HTTP Info   | `sudo nmap -p80,8180 --script default,http-title 192.168.56.102 -oN lab7_http.txt`                                                          | Titles, response codes |
| Vulnerability Sweep | `sudo nmap -sV --script=vuln 192.168.56.102 -oN lab7_vuln.txt`                                                                              | Checks common CVEs     |
| SSH Brute Force     | `sudo nmap -p22 --script=ssh-brute --script-args userdb=usernames.txt,passdb=rockyou.txt,brute.delay=0.2 192.168.56.102 -oN lab7_brute.txt` | Manages lockouts       |

Expected Outcome:

```
• vsftpd backdoor (CVE-2011-2523) detected.
• SSH brute yields msfadmin:msfadmin.
```

Troubleshooting:

```
If scripts outdated: `sudo nmap --script-updatedb`.
```

Reflection:

```
What risks come from running full `vuln` on prod?
```

---

捌 – LAB 8: OUTPUT & CHANGE TRACKING

Leverage `-oA` outputs and `ndiff` to track configuration drift and feed SIEM pipelines.

► STEP‑BY‑STEP

| Task          | Command                                                     | Outcome                        |
| ------------- | ----------------------------------------------------------- | ------------------------------ |
| Initial Scan  | `sudo nmap -sS -A -oA lab8_initial 192.168.56.102`          | XML, greppable, normal outputs |
| Induce Change | On target: `service tomcat6 start`                          | Port 8180 opens                |
| Follow-up     | `sudo nmap -sS -A -oA lab8_followup 192.168.56.102`         | New service detected           |
| Diff          | `ndiff lab8_initial.xml lab8_followup.xml > lab8_delta.txt` | Delta of changes               |

Expected Outcome:

```
• Delta shows `+ 8180/tcp open ajp13`.
```

Troubleshooting:

```
If XML malformed: ensure `-oA` flags precede targets.
```

Reflection:

```
Why choose XML over grepable for long-term records?
```

---

玖 – LAB 9: END‑TO‑END WORKFLOW

Script a full pipeline: discovery, port scan, service/OS, vuln check, report generation.

► STEP‑BY‑STEP

```
#!/usr/bin/env bash
set -e
T=192.168.56.102; D=$(date +%F)
sudo nmap -sn $T -oN ${D}_disc.txt
sudo nmap -sS -p- -T4 $T -oN ${D}_ports.txt
sudo nmap -sV -O -p- $T -oN ${D}_svc_os.txt
sudo nmap --script=vuln -p- $T -oN ${D}_vuln.txt
sudo nmap -sS -A -oX ${D}_full.xml $T
xsltproc /usr/share/nmap/nmap.xsl ${D}_full.xml > ${D}_report.html
echo "[+] ${D}_report.html ready"
```

Expected Outcome:

```
• HTML report generated with collapsible service tree and summary.
```

Troubleshooting:

```
If report fails: install `xsltproc` and correct XSL path.
```

Reflection:

```
List three benefits of automating end-to-end scans.
```

---

拾 – LAB 10: AUTOMATION & SCHEDULING

Use cron and scripts for recurring scans and diff alerts.

► STEP‑BY‑STEP

| Task              | Command                                                                                                                                                                                  |             |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| Nightly Scan      | \`(crontab -l; echo "0 2 \* \* \* /usr/bin/nmap -sS -p22,80,443 -oA \~/nmap-labs/nightly\_\$(date +\\%Y\\%m\\%d) 192.168.56.102")                                                        | crontab -\` |
| Automated Diff    | \`(crontab -l; echo "0 3 \* \* \* ndiff \~/nmap-labs/nightly\_\$(date +\\%Y\\%m\\%d -d '1 day').xml \~/nmap-labs/nightly\_\$(date +\\%Y\\%m\\%d).xml > \~/nmap-labs/nightly\_delta.txt") | crontab -\` |
| Email Alert (Opt) | Configure `mailx` to send `nightly_delta.txt` to your inbox.                                                                                                                             |             |

Expected Outcome:

```
• Empty delta = no change; non-empty flags alert.
```

Troubleshooting:

```
If cron jobs not appearing: check `crontab -l` syntax and escape percent signs.
```

Reflection:

```
Why can hourly scans miss ephemeral containers?
```

---

APPENDIX: REFERENCE FLAG CHEAT-SHEET

| Category       | Flag                        | Memory Hook            |
| -------------- | --------------------------- | ---------------------- |
| Host Discovery | `-sn` / `-Pn`               | Skip ports / No ping   |
| TCP Scans      | `-sT` / `-sS`               | Connect / SYN          |
| UDP            | `-sU`                       | UDP probe              |
| Version        | `-sV`                       | Service version        |
| OS             | `-O`                        | OS fingerprint         |
| Timing         | `-T0`–`-T5`                 | Speed templates        |
| Rate           | `--min-rate` / `--max-rate` | Throttle               |
| NSE            | `--script`                  | Lua engine             |
| Output         | `-oN`/`-oX`/`-oA`           | Normal/XML/All formats |

CONTINUING EDUCATION

```
Nmap Network Scanning (Fyodor’s book)
HackTheBox – Scanning Module
SANS SEC560
Masscan / Rustscan
NSE Scripting (nmap.org/book/nse)
```

REVISION HISTORY

```
2025-07-19: First comprehensive edition with labs 0–10;
updated styling and expanded beginner-friendly explanations.
```

*End of Document*
