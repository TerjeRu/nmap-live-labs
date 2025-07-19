# █▓▒▒░░░ NMAP NETWORK-SCANNING TUTORIAL ░░░▒▒▓█

> **Purpose:** An end-to-end, lab-driven guide to wielding Nmap like a pro—learn *how* to run the scans and *why* each option matters.
>
> **Prerequisites:** Basic Linux CLI navigation; virtualization software; isolated lab network (Host-Only or equivalent).
> **Safety:** Only scan machines within your controlled lab. Scanning random hosts is illegal and may trigger alarms.

## 壱 - LAB TOPOLOGY & SETUP

> Before diving into scans, let’s build a proper playground.

### ► **CORE SETUP: VMs and IPs**

| Role     | VM                    | IP Address     | Notes                                           |
| -------- | --------------------- | -------------- | ----------------------------------------------- |
| Attacker | **Kali Linux 2024.4** | 192.168.56.101 | Pre-loaded with Nmap, Wireshark, Zeek-cut, etc. |
| Target   | **Metasploitable 2**  | 192.168.56.102 | Vulnerable OS with mixed TCP/UDP services.      |
| *(Opt.)* | Zeek/Snort Sensor     | 192.168.56.110 | Monitor packets + IDS alerts in real-time.      |

1. Configure both Attacker and Target VMs on the same isolated network (e.g., VirtualBox Host-Only).
2. Verify connectivity:

   ```bash
   # On Kali:
   ping 192.168.56.102
   ```
3. Ensure `nmap` is installed:

   ```bash
   sudo apt update && sudo apt install nmap -y
   ```

---

## 弐 - NMAP FUNDAMENTALS

> Understanding scan types and timing templates will save you hours.

### ► **CORE CONCEPTS: Scan Methods & Timing**

* **Ping Scan (`-sn`)**: Host discovery only; no port checks.
* **Fast Scan (`-F`)**: Top 100 ports.
* **SYN Scan (`-sS`)**: Stealthy, “half-open” TCP scan (root required).
* **UDP Scan (`-sU`)**: Probes UDP services (slow).
* **Aggressive (`-A`)**: OS detection, version detection, script scanning, traceroute.
* **Timing (`-T0`–`-T5`)**: From paranoid slow to insane fast; `-T4` is ideal for lab work.

---

## 参 - LIVE EXERCISES

> Hands-on scanning from simple to comprehensive.

### ► **Scan 1: Host Discovery**

```bash
nmap -sn 192.168.56.0/24
```

*Discovers live hosts via ARP ping.*

### ► **Scan 2: Quick Port Peek**

```bash
nmap -F -T4 192.168.56.102
```

*Scans 100 most-common ports with aggressive timing.*

### ► **Scan 3: Deep Dive**

```bash
sudo nmap -sS -sU -p- -A --reason -oA metasploitable_full 192.168.56.102
```

* `-p-`: All 65,535 ports.
* `--reason`: Explains port state conclusions.
* `-oA`: Saves `.nmap`, `.gnmap`, `.xml` outputs.

> **Expected Outcome:** A complete inventory of TCP/UDP services, version info, OS guess, and script results.

---

## 四 - ANALYSIS & NEXT STEPS

> Use your scan results as the roadmap for enumeration and exploitation.

1. Open `metasploitable_full.nmap` and review:

   * Version strings → research exploits.
   * Open UDP ports → potential SNMP, DNS, etc.
2. Pipe results to grep or use `ndiff` for scan comparisons.
3. Feed hostnames/IPs into other tools: `enum4linux`, `nikto`, `ssh`, etc.

---

## 五 - EXTENSIONS & AUTOMATION

> Level up with scripts and integrations.

* **Masscan + Nmap**: Rapid host discovery.
* **Nmap Scripting Engine (NSE)**: Automate vulnerability checks (`-sC`, `--script vuln`).
* **Output Parsing:** Use XML/grep, Python, or tools like `xsltproc` to generate HTML reports.

—

*Happy scanning! Keep each lab iteration isolated and document your findings for maximum learning.*
