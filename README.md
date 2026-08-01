# EvilLimiter

[![Version](https://img.shields.io/badge/version-1.6.0-blue.svg)](https://github.com/bitbrute/evillimiter)
[![Python](https://img.shields.io/badge/python-3.6+-yellow.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://www.kernel.org/)

**EvilLimiter** is an advanced network management tool that monitors, analyzes, and limits the upload and download bandwidth of devices on a local network (LAN) without requiring administrative or physical access to the network router.

It employs ARP spoofing (Man-in-the-Middle) paired with Linux Traffic Control (`tc`) to shape and restrict network traffic to and from targeted hosts.

---

## ⚡ Features

- **Bandwidth Limiting**: Restrict upload and/or download speeds on targeted hosts (`100kbit`, `1mbit`, `10mbit`, etc.).
- **Host Blocking**: Completely cut off internet access for selected devices on the LAN.
- **Independent Directional Control**: Limit upload traffic, download traffic, or both simultaneously.
- **Traffic Monitoring**: Interactively monitor real-time upload and download bandwidth usage per host.
- **Traffic Analysis**: Analyze host bandwidth utilization over custom durations without applying limits.
- **Flexible Target Selection**: Select targets by ID, range (`1-5`), comma-separated list (`1,3,5`), `all`, IP address, or MAC address.
- **Host Watcher**: Automatically monitor network reconnections and track hosts IP address changes.
- **State Save & Load**: Save discovered hosts and custom configurations to restore session states.
- **Stealth Mode**: Suppress local ICMP/IP leakage and inbound service probes to maintain low visibility.
- **System Diagnostics**: Built-in `doctor` command to diagnose system binaries, firewall, and dependency states.

---

## 🛠️ Requirements & Dependencies

### Operating System
- **Linux** (Ubuntu, Debian, Kali Linux, Arch Linux, Fedora, etc.)
- **Root privileges** (required for ARP spoofing and `iptables`/`tc` manipulation)

### System Tools
- `python` (v3.6 or higher)
- `iptables`
- `tc` (Linux Traffic Control, included in `iproute2`)

### Python Libraries
- `scapy`
- `terminaltables`
- `colorama`
- `netifaces`
- `netaddr`
- `tqdm`

---

## 🚀 Installation

### Option 1: Install via PyPI
```bash
sudo pip install evillimiter
```

### Option 2: Install from Source
```bash
git clone https://github.com/bitbrute/evillimiter.git
cd evillimiter
sudo python setup.py install
```

---


## 📖 Command-Line Options

Launch EvilLimiter with root privileges:

```bash
sudo evillimiter [options]
```

### Available Flags

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-i` | `--interface` | Network interface connected to target network (e.g., `eth0`, `wlan0`). Auto-resolved if omitted. |
| `-g` | `--gateway-ip` | Gateway IP address. Auto-resolved if omitted. |
| `-m` | `--gateway-mac` | Gateway MAC address. Auto-resolved if omitted. |
| `-n` | `--netmask` | Network netmask (e.g., `255.255.255.0`). Auto-resolved if omitted. |
| `-f` | `--flush` | Flush existing `iptables` rules and `tc` qdisc settings before launching. |
| | `--stealth` | Enable stealth mode (suppresses ICMP leakage and service probes). |
| | `--colorless` | Disable colored terminal output. |

---

## 💻 Interactive Console Commands

Once inside the interactive shell (`(Main) >>>`), the following commands are available:

### 1. Host Discovery & Listing

- **`scan [--range <IP range>]`**  
  Scans the local network for active hosts using ARP requests.
  ```bash
  (Main) >>> scan
  (Main) >>> scan --range 192.168.1.1-192.168.1.50
  ```

- **`hosts [--force]`**  
  Displays a table of discovered hosts with IDs, IP addresses, MAC addresses, hostnames, and current bandwidth limits.
  ```bash
  (Main) >>> hosts
  (Main) >>> hosts --force
  ```

- **`add <IP> [--mac <MAC>]`**  
  Manually add a host to the host table.
  ```bash
  (Main) >>> add 192.168.1.45
  (Main) >>> add 192.168.1.45 --mac 00:11:22:33:44:55
  ```

---

### 2. Bandwidth Limiting & Blocking

Target host specification accepts:
- Single ID: `2`
- Multiple IDs: `1,3,4`
- Range: `1-5`
- Keyword: `all`
- IP address: `192.168.1.100`
- MAC address: `00:11:22:33:44:55`

- **`limit <ID> <rate> [--upload] [--download]`**  
  Limits bandwidth of specified target(s). Rates can be specified in `kbit` or `mbit` (e.g., `500kbit`, `2mbit`).
  ```bash
  (Main) >>> limit 2 1mbit
  (Main) >>> limit 1,3 500kbit --upload
  (Main) >>> limit all 2mbit --download
  ```

- **`block <ID> [--upload] [--download]`**  
  Completely blocks internet traffic for target host(s).
  ```bash
  (Main) >>> block 4
  (Main) >>> block 1-3 --download
  ```

- **`free <ID>`**  
  Removes bandwidth restrictions and restores original connectivity for target host(s).
  ```bash
  (Main) >>> free 2
  (Main) >>> free all
  ```

---

### 3. Monitoring & Analysis

- **`monitor [--interval <ms>]`**  
  Displays live upload and download throughput for all discovered network hosts.
  ```bash
  (Main) >>> monitor
  (Main) >>> monitor --interval 2000
  ```

- **`analyze <ID> [--duration <sec>] [--export <file>]`**  
  Analyzes real-time traffic usage of specified hosts over a period without enforcing speed limits.
  ```bash
  (Main) >>> analyze 2 --duration 60
  (Main) >>> analyze 1,3 --duration 120 --export log.csv
  ```

---

### 4. Host Watcher & Reconnection Tracking

- **`watch add <ID>`** / **`watch remove <ID>`**  
  Add or remove hosts from the watcher list to track IP address changes and reconnections.
  ```bash
  (Main) >>> watch add 2
  (Main) >>> watch remove 2
  ```

- **`watch set <attribute> <value>`**  
  Configure watcher options.

---

### 5. Diagnostics & Session Management

- **`doctor`** / **`diagnostics`**  
  Runs a diagnostic check on system environment, firewall rules, required binaries, and active network handles.
  ```bash
  (Main) >>> doctor
  ```

- **`save <filename>`** / **`load <filename>`**  
  Save host state list to a file or load previously saved state.
  ```bash
  (Main) >>> save session.json
  (Main) >>> load session.json
  ```

- **`clear`**  
  Clears the terminal screen.

- **`quit`** / **`exit`**  
  Exits EvilLimiter and automatically restores normal network configuration for all hosts.

---

## 🔒 How It Works

1. **ARP Spoofing (MITM)**: EvilLimiter periodically sends crafted ARP reply packets to target host(s) and the default gateway, convincing target devices that the host machine is the router (and vice versa).
2. **Packet Forwarding**: IP forwarding is enabled so network packets flow smoothly through the host system without dropping unless configured to block.
3. **Traffic Control (`tc`) & Firewall (`iptables`)**: Linux Traffic Control HTB (Hierarchical Token Bucket) queues and IFB (Intermediate Functional Block) pseudo-interfaces shape ingress and egress rate limits on network packets in real-time.
4. **Emergency Signals & Cleanup**: Upon normal termination (`quit`/`exit`) or unexpected termination (SIGINT/SIGTERM), EvilLimiter restores original ARP caches and removes custom `tc` qdiscs and `iptables` rules.

## ⚖️ Disclaimer

**EvilLimiter** is created for educational, research, and legitimate network management purposes only. Using this tool on networks without prior explicit consent from the network owner or administrator is illegal. The author and contributors accept no responsibility for misuse or illegal activities conducted with this software.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
