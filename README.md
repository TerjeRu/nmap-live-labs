```markdown
# Nmap Network‑Scanning Tutorial – Enterprise Edition (Comprehensive)

> **Purpose**
>
> Deliver an end‑to‑end, lab‑driven curriculum that not only shows *how* to operate Nmap but digs into the *why* behind every flag, packet, and log entry. The guide scales from a two‑VM sandbox to a small enterprise test range and includes blue‑team instrumentation so defenders can follow along.
>
> **Read‑Me First**  
> • **Running time**: 8–12 hours for the core path; ~20 hours with every extension.  
> • **Prerequisites**: Basic Linux CLI navigation. No prior networking or security tooling required.  
> • **Safety**: Perform all activities on **isolated networks only**. Port‑scanning random hosts can trigger legal and policy violations.
>
> **Minimum Lab Topology**
>
> | Role | VM | Suggested IP | Rationale |
> |------|----|--------------|-----------|
> | Attacker | **Kali Linux 2024.4** | 192.168.56.101 | Comes pre‑loaded with Nmap, Wireshark, Zeek‑cut, etc. |
> | Target   | **Metasploitable 2** | 192.168.56.102 | Purpose‑built vulnerable OS with mixed TCP/UDP services. |
> | *(Optional)* Sensor | Zeek/Snort VM | 192.168.56.110 | Lets you watch packets + IDS alerts in real‑time. |
>
> **Audience** — Aspiring SOC analysts, junior penetration testers, red‑team apprentices, and sysadmins who want to demystify port‑scanning.
>
> **How to use this guide**
> 1. Skim the *Concept Brief* at the top of each lab. If something feels fuzzy, read the inline **Deep Dive** call‑outs.
> 2. Complete the **Live Lab** with your keyboard—*no skipping ahead*.
> 3. Validate against **Expected Outcome** and investigate differences; they are learning opportunities.
> 4. Study the **Blue‑Team View** to understand how your actions surface in logs.
> 5. Answer the **Reflection Prompt** in your own words. This cements retention.

---

## Table of Contents

0. [Lab 0  – Environment Preparation](#lab-0)  
1. [Lab 1  – Host Discovery](#lab-1)  
2. [Lab 2  – TCP Scanning Fundamentals](#lab-2)  
3. [Lab 3  – UDP Scanning Basics](#lab-3)  
4. [Lab 4  – Service & OS Detection](#lab-4)  
5. [Lab 5  – Timing and Performance Tuning](#lab-5)  
6. [Lab 6  – Firewall / IDS Evasion](#lab-6)  
7. [Lab 7  – Nmap Scripting Engine (NSE)](#lab-7)  
8. [Lab 8  – Output Handling & Change Tracking](#lab-8)  
9. [Lab 9  – Comprehensive Assessment](#lab-9)  
10. [Lab 10  – Bash Automation & Scheduling](#lab-10)  
11. [Appendix – Reference Flag Cheat‑sheet](#appendix)  
12. [Further Reading & Next Steps](#continuing-education)  
13. [Revision History](#revision-history)

---

<a id="lab-0"></a>
## Lab 0  – Environment Preparation

### Objective
Establish a hermetically sealed playground where traffic is confined to the host‑only network and every required tool is installed. Mis‑configured adapters are the #1 cause of *"Why is nothing responding?"* panic on day one.

### Deep Dive – Why Host‑Only?
Bridged adapters leak scans to your corporate LAN—hello, HR call. NAT can hide your target from the attacker VM. Host‑only provides a *Goldilocks* middle ground: isolation plus full Layer‑2 visibility (e.g., ARP works out of the box).

### Pre‑Lab Checklist
1. **Snapshots**: Take a VM snapshot now; it’s your instant rewind button.
2. **USB Wi‑Fi** *(Optional)*: If you intend to test wireless later, pass through a compatible adapter.

### Step‑by‑Step
| # | Action | Command | What to Look For | Why It Matters |
|---|--------|---------|------------------|----------------|
| 1 | Configure network adapters | *Hypervisor UI* | Both VMs show **Host‑Only Adapter** | Guarantees isolation |
| 2 | Confirm IPs inside Kali | `ip -4 -br addr show` | `192.168.56.101/24` on `eth0` | Verifies DHCP/static config |
| 3 | Confirm IPs inside Metasploitable | `ifconfig eth0` | `192.168.56.102` | Same subnet ensures L2 reachability |
| 4 | Ping sweep | `ping -c3 192.168.56.102` (from Kali) | Three ICMP echo‑replies | Tests basic connectivity |
| 5 | Update packages | `sudo apt update && sudo apt upgrade -y` | No errors | Up‑to‑date tools eliminate bug‑hunt detours |
| 6 | Install toolset | `sudo apt install nmap wireshark tshark ndiff xsltproc -y` | `nmap 7.95` or newer | Adds diff & report utilities |
| 7 | *(Optional)* Deploy sensor VM | Follow Zeek quick‑start docs | Zeek listening on `eth0` | Mirrors defender viewpoint |

### Expected Outcome
* Both VMs ping each other with <1 ms latency.  
* `nmap --version` prints a version ≥ 7.95.  
* Sensor (if used) shows only ICMP echoes between .101 ↔ .102.

### Troubleshooting Tips
| Symptom | Possible Cause | Fix |
|---------|----------------|-----|
| `Destination Host Unreachable` | Wrong adapter type | Switch to Host‑Only & reboot VM |
| Packet loss in ping | Hypervisor promiscuous mode off | Enable promiscuous for Host‑Only net |

### Blue‑Team View
Open Zeek’s `conn.log` and Wireshark simultaneously. Verify that only ICMP and ARP traffic appears. This baseline will help you spot anomalies later.

### Reflection Prompt
> In one paragraph, explain why isolating the lab network prevents false positives in enterprise IDS and accidental policy violations.

---

<a id="lab-1"></a>
## Lab 1  – Host Discovery

### Concept Brief
Before flinging thousands of SYN packets, you need to know *which* IPs are even alive. Nmap’s discovery engine uses customizable probes—ICMP, ARP, TCP, or UDP—to elicit a response. Think of it as a *doorbell* before you attempt to pick the lock.

#### Deep Dive – Probe Selection Logic
* **Local subnet**: ARP is king; routers don’t forward it, so the noise stays local.  
* **Remote targets**: ICMP echo‑request plus a couple of TCP SYNs (default) gives decent coverage.  
* **Firewalled hosts**: `-Pn` disables host discovery so you can brute‑force your way in; but you’ll waste time scanning dead IPs.

### Live Lab (Hands‑On)

1. **Open Wireshark** on Kali. Apply display filter:
```

icmp or arp or tcp.port==80 or tcp.port==443

````
*Why?*—This highlights only the discovery probes for clarity.
2. **Run four discovery modes** and save each output:
| Task | Command | Note |
|------|---------|------|
| ARP ping sweep | `sudo nmap -sn 192.168.56.0/24 -oN arp_scan.txt` | Fastest on LAN |
| ARP‑only (forced) | `sudo nmap -sn -PR 192.168.56.0/24 -oN arp_only.txt` | Explicit flag for teaching |
| TCP SYN ping | `sudo nmap -sn -PS80,443 192.168.56.102 -oN syn_ping.txt` | Mimics web traffic |
| No discovery | `sudo nmap -sn -Pn 192.168.56.102 -oN none.txt` | For heavily filtered nets |
3. **Observe** Wireshark in real‑time; correlate packet counts to Nmap’s timing stats.
4. **Document** runtime for each command in a personal logbook.

### Expected Outcome
* ARP scans complete in <2 seconds.  
* `-Pn` produces **zero** packets in Wireshark because discovery is skipped.

### What to Look For & Why
| Indicator | Interpretation | Why It Matters |
|-----------|---------------|----------------|
| ARP who‑has 192.168.56.1xx | Nmap broadcast sweep | Good baseline traffic |
| SYN to 80/443 | TCP ping technique | May bypass ICMP‑filtered hosts |
| Absence of replies | Host is down *or* ICMP blocked | Drives choice: retry with different probes or flag as dead |

### Blue‑Team View
Zeek’s `notice.log` may raise *“Address Scan”* warnings when it sees many ARP requests. Compare alert volume between ARP and TCP probes.

### Reflection Prompt
> In two sentences, justify when `-Pn` is appropriate and outline its trade‑offs in scan duration and false‑positive risk.

---

<a id="lab-2"></a>
## Lab 2  – TCP Scanning Fundamentals

### Concept Brief
TCP scanning is the bread‑and‑butter of reconnaissance. Nmap’s *Connect* (`-sT`) and *SYN* (`-sS`) modes differ primarily in *how much of the handshake* they perform. Fewer packets → faster, stealthier—but root access is required.

#### Deep Dive – TCP State Machine Recap
`CLOSED → SYN_SENT → SYN_RECEIVED → ESTABLISHED` is the classic handshake dance. A half‑open SYN scan bails after the SYN‑ACK/RST, never reaching ESTABLISHED, leaving fewer log artifacts on the target.

### Live Lab
1. **Start Wireshark** capture on Kali (`eth0`).
2. **Connect Scan (full handshake)**:
```bash
nmap -sT -p 1-1024 192.168.56.102 -oN connect.txt
````

3. **SYN Scan (half‑open)**:

   ```bash
   sudo nmap -sS -p 1-1024 192.168.56.102 -oN syn.txt
   ```
4. **Count packets**: Wireshark → *Statistics → Conversations → TCP*; note the packet and byte totals.
5. **Compare outputs**: `diff -u connect.txt syn.txt` and observe port state differences.
6. **Extension – Flag Playground**:

   | Flag   | Command                                              | Use‑Case                           |
   | ------ | ---------------------------------------------------- | ---------------------------------- |
   | FIN    | `sudo nmap -sF -p 1-1024 192.168.56.102 -oN fin.txt` | Bypassing some stateless firewalls |
   | ACK    | `sudo nmap -sA -p 1-1024 192.168.56.102 -oN ack.txt` | Mapping firewall rules             |
   | Window | `sudo nmap -sW -p 445 192.168.56.102 -oN win.txt`    | Rarely used fingerprint trick      |

### Expected Outcome

* SYN scan uses \~40–60 % fewer packets than the connect scan.
* FIN/ACK scans label ports as *filtered* vs *unfiltered*—they are *state enumeration* techniques, not service detectors.

### Things to Observe

| Output Clue                  | Interpretation                | Next Action                       |
| ---------------------------- | ----------------------------- | --------------------------------- |
| “80/tcp open http”           | Target runs a web server      | Queue up NSE `http-enum` in Lab 7 |
| High packet loss in SYN scan | IDS dropping half‑open probes | Retry with `--max-retries 2`      |

### Troubleshooting

| Problem                        | Cause                   | Remedy                           |
| ------------------------------ | ----------------------- | -------------------------------- |
| `SYN scan requires root` error | Running as non‑root     | Use `sudo` or fall back to `-sT` |
| Missed ports compared to `-sT` | SYN probes rate‑limited | Lower timing template to `-T2`   |

### Blue‑Team View

*Connect scans* generate full connection logs: `/var/log/auth.log` (SSH) or Apache `access.log`. *SYN scans* appear as SYN followed by RST in Zeek `conn.log`—less verbose but still detectable.

### Reflection Prompt

> You have user‑level access only. Which scan type do you pick and how will that impact detection? Defend your answer with two technical points.

---

<a id="lab-3"></a>

## Lab 3  – UDP Scanning Basics

### Concept Brief

UDP is connectionless; no handshake means *silence* could be “open but quiet” *or* “filtered and dropped.” Nmap therefore relies on ICMP Type 3 Codes (port unreachable, host unreachable, admin‑prohibited) and timeouts to guess each port’s state. Patience is mandatory.

#### Deep Dive – How Nmap Classifies UDP Responses

* **ICMP Type 3 Code 3** → *closed*
* **Any other ICMP Type 3** → *filtered*
* **No response** → *open|filtered* (ambiguous)

### Live Lab

| Step | Command                                                                                          | Rationale                                     |                              |
| ---- | ------------------------------------------------------------------------------------------------ | --------------------------------------------- | ---------------------------- |
| 1    | `sudo nmap -sU --top-ports 20 192.168.56.102 -oN udp_top20.txt`                                  | Quick scan of the most common UDP ports       |                              |
| 2    | `sudo nmap -sU -p 161 --script snmp-info 192.168.56.102 -oN snmp.txt`                            | Targeted SNMP probe on port 161               |                              |
| 3    | `sudo nmap -sU --top-ports 20 --max-retries 2 --host-timeout 3m 192.168.56.102 -oN udp_fast.txt` | Aggressive timing tweak to finish under 3 min |                              |
| 4    | *(Bonus)* Verify with netcat                                                                     | `nc -vu 192.168.56.102 161`                   | Manual check for SNMP banner |

### Expected Outcome

* At least one port appears as *open|filtered* (likely 137/138 if NetBIOS enabled).
* SNMP script returns system information if the service exists.

### Observation Checklist

| Evidence                        | Meaning                                               |                                                   |
| ------------------------------- | ----------------------------------------------------- | ------------------------------------------------- |
| ICMP Type 3 Code 3 in Wireshark | Port is **closed**; scanner received explicit refusal |                                                   |
| No ICMP, no UDP reply           | Port is \*\*open                                      | filtered\*\*; need app‑level probe or credentials |

### Troubleshooting

| Issue                  | Diagnosis                     | Fix                                        |
| ---------------------- | ----------------------------- | ------------------------------------------ |
| Scan stuck for >10 min | Retries too high (default 10) | Add `--max-retries 2 --host-timeout 3m`    |
| False negatives        | Host firewall drops ICMP      | Combine UDP scan with targeted NSE scripts |

### Blue‑Team View

Monitor Zeek’s `icmp.log` for Type 3 spikes. A burst of *Destination Unreachable* often signals inbound UDP scanning.

### Reflection Prompt

> UDP ambiguity frustrates both attackers and defenders. Suggest one offensive and one defensive technique to reduce *open|filtered* uncertainty.

---

<a id="lab-4"></a>

## Lab 4  – Service & OS Detection

### Concept Brief

Open ports are just numbers; you need banners and fingerprints to turn them into actionable intel. Nmap’s `-sV` and `-O` options send additional probes—version queries, TCP options, ICMP quirks—to build a service catalog and OS guess.

#### Deep Dive – How `-sV` Works Under the Hood

Each probe is a small payload (e.g., HTTP GET `/`, FTP `FEAT`) with a known fingerprint code. Nmap matches the banner against its `nmap-service-probes` database, then refines guesses with RFC compliance quirks like TCP sequence predictability.

### Live Lab

| # | Action                     | Command                                                              |
| - | -------------------------- | -------------------------------------------------------------------- |
| 1 | Baseline version detection | `sudo nmap -sV -p 21,22,80 192.168.56.102 -oN versions.txt`          |
| 2 | OS fingerprinting          | `sudo nmap -O 192.168.56.102 -oN os.txt`                             |
| 3 | All‑in‑one aggressive      | `sudo nmap -A 192.168.56.102 -oN aggressive.txt`                     |
| 4 | *(Bonus)* Intensity tuning | `sudo nmap -sV --version-intensity 9 192.168.56.102 -oN intense.txt` |

### Expected Outcome

* `-sV` reveals precise versions (e.g., `vsftpd 2.3.4`, `Apache 2.2.8`).
* `-O` lists OS family (e.g., “Linux 2.6.X”) with a confidence score.

### Observation Checklist

| Field                                   | Significance                                                |
| --------------------------------------- | ----------------------------------------------------------- |
| `Service Info: OS: Unix`                | Quick OS hint w/o `-O`                                      |
| `Aggressive OS guesses`                 | Multiple matches—look at *percentage* to assess reliability |
| `Too many fingerprints match this host` | Generic result; rerun with `--osscan-limit`                 |

### Troubleshooting

| Symptom                                                                                                 | Likely Cause                    | Mitigation                                            |
| ------------------------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------- |
| `OS detection skipped because no root privileges`                                                       | Self‑explanatory                | Use `sudo`, or rely on TTL heuristics (`-O` disabled) |
| `Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port` | Target is fully open/closed set | Add fake closed port with `--top-ports 1`             |

### Blue‑Team View

Version probes often trigger *Low‑Severity: Banner Grabbing* IDS signatures. OS detection may set off *Malformed TCP Options* alerts in advanced IDS like Suricata.

### Reflection Prompt

> Articulate why running `-sV` on *all* 65 535 ports is counter‑productive. Include both offensive and defensive angles.

---

<a id="lab-5"></a>

## Lab 5  – Timing and Performance Tuning

### Concept Brief

Speed kills—sometimes your scan, sometimes your stealth. Nmap’s timing templates (`-T0` to `-T5`) bundle sane presets for parallelism, delay, and retries. Fine‑grain knobs (`--min-rate`, `--max-rate`, `--max-retries`) let you tailor scans to flaky networks or tight windows.

#### Deep Dive – Anatomy of a Timing Template

* **Parallelism**: How many probes can run at once (host and per‑host).
* **Delay**: Minimum wait between probes.
* **Timeouts**: How long to wait for answers before marking packet lost.
* Template `-T4` is generally safe on LANs; `-T5` removes most safety nets.

### Live Lab

1. **Timing Template Shoot‑out**:

   ```bash
   for T in 3 4 5; do
     echo "Running -T$T…"
     sudo nmap -sS -p 1-1000 -T$T 192.168.56.102 -oN T${T}.txt
   done
   ```

   Record runtime (`time` shell builtin) and open‑port count.
2. **Custom Rate Control**:

   ```bash
   sudo nmap -sS -p 1-1000 --min-rate 50 --max-rate 100 --max-retries 2 192.168.56.102 -oN rate_ctl.txt
   ```
3. **Packet Loss Simulation** *(Optional)*: Use `tc` on the sensor VM to introduce 10 % loss and rerun scans.

### Expected Outcome

* `-T5` halves runtime compared to `-T3` but may miss occasional ports under induced loss.
* Custom rate scan finishes close to the theoretical packet budget (ports × min‑rate).

### Observation Matrix

| Template | Runtime | Ports Found | Notes                          |
| -------- | ------- | ----------- | ------------------------------ |
| `-T3`    | `≈35 s` |  10         | Baseline                       |
| `-T4`    | `≈18 s` |  10         | Good balance                   |
| `-T5`    | `≈9 s`  |  9          | Dropped one port 22 under loss |

*(Numbers will vary; focus on trend.)*

### Blue‑Team View

Plot Zeek `conn.log` entries by timestamp. `-T5` appears as a sharp spike; `-T3` is smoother. Analysts often pivot on these burst patterns to flag scans.

### Reflection Prompt

> Give two real‑world scenarios where ultra‑slow templates (`-T0/-T1`) are the right call despite hours‑long runtimes.

---

<a id="lab-6"></a>

## Lab 6  – Firewall / IDS Evasion

### Concept Brief

Evasion flags twist packet morphology to slip past simple rulesets. They are *best‑effort,* not invisibility cloaks—modern IDS/IPS often reassemble fragments and flag decoys.

#### Deep Dive – Why Fragmentation Sometimes Works

Some stateless ACLs match only the first fragment (offset 0). By stuffing TCP headers across multiple fragments (`-f`), the rule sees an orphaned IP header and lets it through. Stateful devices reassemble and catch you.

### Live Lab

0. **Reset Sensor Counters**: Clear Zeek logs (`sudo rm *.log`) to isolate this lab.
1. **Baseline Scan (no evasion)**

   ```bash
   sudo nmap -sS -p 445 192.168.56.102 -oN no_evasion.txt
   ```
2. **Fragmentation**

   ```bash
   sudo nmap -sS -p 445 -f 192.168.56.102 -oN frag.txt
   ```
3. **Decoys**

   ```bash
   sudo nmap -sS -p 445 -D RND:5 192.168.56.102 -oN decoy.txt
   ```
4. **MAC + Source‑Port Spoof**

   ```bash
   sudo nmap -sS -p 445 --spoof-mac 0 --source-port 53 192.168.56.102 -oN mac53.txt
   ```
5. **Full Kitchen Sink** (Risk of triggering IPS block)

   ```bash
   sudo nmap -sS -p 445 -f -D RND:5 --spoof-mac 0 --data-length 60 192.168.56.102 -oN combo.txt
   ```

### Expected Outcome

* Target still shows `445/tcp open microsoft-ds` in all scans.
* Sensor logs fewer or no alerts for fragmented packets if IDS lacks reassembly.

### Evaluation Grid

| Technique | Packets Seen in Sensor | Alert Fired?      | CPU Cost (Scan Time) |
| --------- | ---------------------- | ----------------- | -------------------- |
| None      | 3                      | Yes               | Low                  |
| Fragment  | 6                      | Maybe             | Medium               |
| Decoy     | 24 (5× sources)        | Yes, multiple IPs | High                 |
| MAC+53    | 3                      | Maybe             | Low                  |
| Combo     | 30                     | Maybe             | Very High            |

### Blue‑Team View

Decoys explode *source‑IP cardinality* in Zeek. A spike of short‑lived flows from random IPs can itself be a giveaway.

### Reflection Prompt

> Which evasion flag yielded the smallest alert footprint on your sensor, and why do you think that is? Include a hypothesis about the sensor’s detection logic.

---

<a id="lab-7"></a>

## Lab 7  – Nmap Scripting Engine (NSE)

### Concept Brief

NSE turns Nmap into a Swiss‑Army knife: brute‑forcers, CVE scanners, protocol misconfig checks, even cryptocurrency miners (don’t). Scripts run in parallel with the port scan to save round‑trips.

#### Deep Dive – Anatomy of an NSE Script

Each script is a Lua file with *categories* (`default`, `safe`, `vuln`, `brute`, etc.). You can select by category, filename, or regex. Script arguments fine‑tune behavior (credentials, paths, thresholds).

### Live Lab

1. **Default HTTP Enumeration**

   ```bash
   sudo nmap -p 80 --script default 192.168.56.102 -oN http_default.txt
   ```
2. **Vulnerability Sweep Across Open Ports**

   ```bash
   sudo nmap -sV --script vuln 192.168.56.102 -oN vuln.txt
   ```
3. **Targeted SSH Brute‑Force** *(lab credentials: msfadmin/msfadmin)*

   ```bash
   sudo nmap -p 22 --script ssh-brute --script-args userdb=/usr/share/wordlists/metasploit/unix_users.txt,passdb=/usr/share/wordlists/metasploit/unix_passwords.txt 192.168.56.102 -oN ssh_brute.txt
   ```
4. **Custom Script Execution** *(Optional)*

   1. Copy `scripts/http-title.nse` to `~/custom.nse`.
   2. Edit banner text output.
   3. Run: `sudo nmap -p 80 --script ./custom.nse 192.168.56.102`.

### Expected Outcome

* `vuln` scripts flag **vsftpd 2.3.4 Backdoor CVE‑2011‑2523**.
* SSH brute prints `Discovered credentials msfadmin:msfadmin` within a few minutes.

### Script Triage Tips

| Field                       | Action                               |
| --------------------------- | ------------------------------------ |
| `State: VULNERABLE`         | Add to immediate report              |
| `Risk Factor: High/Med/Low` | Prioritize remediation               |
| `Exploit ease: Easy`        | Consider proving exploit to validate |

### Blue‑Team View

SSH brute‑force floods `/var/log/auth.log` with “Failed password” lines. Zeek’s `ssh.log` will list hundreds of attempts with `status = failed-password`.

### Reflection Prompt

> Discuss how NSE’s parallel execution model can both reduce scan time *and* increase sensor visibility. Provide one mitigation for defenders.

---

<a id="lab-8"></a>

## Lab 8  – Output Handling & Change Tracking

### Concept Brief

Nmap supports four primary output formats (Normal, XML, Grepable, Script‑Kiddie… kidding, `-oG`). Consistent filenames (`YYYYMMDD_target.xml`) enable **delta analysis** with `ndiff`.

### Live Lab

1. **Master Scan – All Formats**

   ```bash
   sudo nmap -sS -A -oA initial 192.168.56.102
   ```
2. **Induce Change**: On Metasploitable, start Tomcat: `service tomcat6 start` (opens port 8180).
3. **Follow‑Up Scan**

   ```bash
   sudo nmap -sS -A -oA followup 192.168.56.102
   ```
4. **Diff the XMLs**

   ```bash
   ndiff initial.xml followup.xml > delta.txt
   cat delta.txt
   ```
5. **Optional – HTML Report**

   ```bash
   xsltproc /usr/share/nmap/nmap.xsl followup.xml > followup.html
   xdg-open followup.html
   ```

### Expected Outcome

`delta.txt` lists:

```
+ 8180/tcp open  http
```

No other changes.

### Automation Idea

Add `ndiff` output to your SIEM ingest path. Alert when new high‑risk ports appear.

### Blue‑Team View

A service coming online should also be caught by host‑based agents. Correlate `delta.txt` with any EDR process start alerts.

### Reflection Prompt

> XML is verbose; why do most enterprise parsers prefer it over Grepable or Normal output?

---

<a id="lab-9"></a>

## Lab 9  – Comprehensive Assessment

### Concept Brief

Time to synthesize everything: discovery → port enumeration → service/OS fingerprint → NSE vuln scan → diff. The deliverable is a concise report suitable for management *and* technical staff.

### Live Lab

1. **Download the helper script** `full_workflow.sh` (script snippet below). Make it executable: `chmod +x full_workflow.sh`.
2. **Script Contents**

   ```bash
   #!/bin/bash
   TARGET="192.168.56.102"
   DATE=$(date +%F)
   echo "[+] Discovery"
   sudo nmap -sn $TARGET -oN ${DATE}_discovery.txt

   echo "[+] Port Sweep"
   sudo nmap -sS -p- -T4 $TARGET -oN ${DATE}_ports.txt

   echo "[+] Service & OS"
   sudo nmap -sV -O -p- --version-intensity 3 $TARGET -oN ${DATE}_service_os.txt

   echo "[+] Vuln Scan"
   sudo nmap --script vuln -p- $TARGET -oN ${DATE}_vuln.txt

   echo "[+] Consolidated XML"
   sudo nmap -sS -A -oX ${DATE}_full.xml $TARGET

   echo "[+] Generate HTML"
   xsltproc /usr/share/nmap/nmap.xsl ${DATE}_full.xml > ${DATE}_report.html
   echo "Report ready: ${DATE}_report.html"
   ```
3. **Run the script**: `./full_workflow.sh`.
4. **Open the HTML report** in a browser and skim each section.
5. **Write a one‑page executive summary** with the template provided in `report_template.md`.

### Expected Outcome

* HTML report enumerates all open ports plus vsftpd CVE.
* Executive summary includes **Impact**, **Likelihood**, **Recommendations**.

### Blue‑Team View

Running the script should flood sensor with predictable scan sequence. Verify your SIEM correlates discovery → port → service → vulns as a multi‑stage incident.

### Reflection Prompt

> List three advantages of automating scans over manual CLI commands. Rank them by ROI in a 10‑host environment.

---

<a id="lab-10"></a>

## Lab 10  – Bash Automation & Scheduling

### Concept Brief

Assets drift—new services enable themselves, patches close ports. Scheduled scans catch these changes. Cron plus `ndiff` provides a poor‑man’s continuous monitoring platform.

### Live Lab

1. **Nightly Scan Job (02:00)**

   ```bash
   (crontab -l 2>/dev/null; \
    echo "0 2 * * * /usr/bin/nmap -sS -p 22,80,443 -oA nightly_$(date +\%F) 192.168.56.102") | crontab -
   ```
2. **Nightly Diff Job (03:00)**

   ```bash
   (crontab -l; \
    echo "0 3 * * * /usr/bin/ndiff $(ls -tr nightly_*.xml | tail -n2 | head -n1) $(ls -tr nightly_*.xml | tail -n1) > /tmp/nightly_delta.txt") | crontab -
   ```
3. **Email Alert on Change** *(Optional)*

   ```bash
   (crontab -l; \
    echo "5 3 * * * grep -q '+' /tmp/nightly_delta.txt && mail -s 'Nmap Delta Detected' you@example.com < /tmp/nightly_delta.txt") | crontab -
   ```
4. **Verify Cron**: `crontab -l` should list three jobs.

### Expected Outcome

* New XML each night: `nightly_YYYY-MM-DD.xml`.
* `/tmp/nightly_delta.txt` contains diffs only when a port changes state.

### Limitations & Mitigations

| Limitation                  | Impact                                | Mitigation                                    |
| --------------------------- | ------------------------------------- | --------------------------------------------- |
| Cron misses transient ports | Short lived services escape detection | Increase scan frequency or deploy host agents |
| XML files pile up           | Disk bloat                            | Logrotate or prune older than 30 days         |
| Static port list            | Misses new high ports                 | Quarterly full‑range scans                    |

### Blue‑Team View

Correlate `ndiff`‑triggered email alerts with SIEM service‑start events to cross‑validate detection.

### Reflection Prompt

> Why should scheduled external scans be *complemented* with host‑based telemetry in a modern SOC?

---

<a id="appendix"></a>

## Appendix – Reference Flag Cheat‑sheet

| Category       | Flag              | Purpose               | Common Pitfall                                   |
| -------------- | ----------------- | --------------------- | ------------------------------------------------ |
| Host Discovery | `-sn`             | Disable port scan     | Confused with “silent”; still sends probes       |
|                | `-Pn`             | Skip discovery        | Scans dead IPs if misused                        |
| TCP Scans      | `-sT`             | Connect scan          | Requires no root; very noisy                     |
|                | `-sS`             | SYN scan              | Needs root; half‑open only                       |
|                | `-sF`             | FIN scan              | Won’t work against Windows targets               |
| UDP            | `-sU`             | UDP scan              | Slower, ambiguous                                |
| Service/OS     | `-sV`             | Version detection     | Database fingerprint staleness                   |
|                | `-O`              | OS fingerprint        | Needs both open & closed port                    |
| Timing         | `-T0‑T5`          | Templates             | `-T5` drops packets on WAN                       |
|                | `--min-rate`      | Floor for packet rate | Don’t set > network capacity                     |
| NSE            | `--script`        | Choose scripts        | `default` ≠ `safe` (default runs intrusive ones) |
| Output         | `-oN/-oX/-oG/-oA` | Files                 | Forgetting `-oA` → no XML to diff                |

---

<a id="continuing-education"></a>

## Further Reading & Next Steps

| Resource                           | Why It Matters                                       |
| ---------------------------------- | ---------------------------------------------------- |
| *Nmap Network Scanning* (book)     | Official bible by Fyodor, deep protocol theory       |
| Nmap GitHub Issues                 | Bleeding‑edge bug discussions                        |
| NSE Dev Guide                      | Write custom scripts to automate niche tasks         |
| Hack The Box – *Nmap* Module       | Guided CTF challenges on scanning                    |
| SANS SEC560 Labs                   | Enterprise simulation networks for red/blue practice |
| Masscan & Rustscan                 | Complementary speed‑scanning tools                   |
| Wireshark Display Filter Reference | Crucial for packet‑level confirmation                |

---

<a id="revision-history"></a>

## Revision History

| Date       | Changes                                                                                                    |
| ---------- | ---------------------------------------------------------------------------------------------------------- |
| 2025‑07‑19 | Comprehensive rewrite – added Deep Dive, Troubleshooting, Observation tables, Labs 9‑10 automation details |
| 2025‑07‑19 | Initial release (superseded)                                                                               |

---

*End of Document*

```
```
