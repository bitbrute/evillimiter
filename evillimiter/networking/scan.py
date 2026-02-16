import sys
import time
import socket
import struct
import subprocess
import threading
from netaddr import EUI, NotRegisteredError
from scapy.all import (  # pylint: disable=no-name-in-module
    srp, sr1, sr, Ether, ARP, IP, ICMP, TCP, UDP,
    conf, sniff, Raw
)

from .host import Host
from evillimiter.console.io import IO


class HostScanner(object):
    _SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    # Common ports for TCP SYN discovery (devices often listen on these)
    _TCP_DISCOVERY_PORTS = [80, 443, 8080, 22, 554, 8443, 5000, 9100, 62078]
    # mDNS multicast address and port
    _MDNS_ADDR = '224.0.0.251'
    _MDNS_PORT = 5353
    # NetBIOS Name Service
    _NBNS_ADDR = '255.255.255.255'
    _NBNS_PORT = 137

    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange
        self.timeout = 5       # increased from 2s — IndiHome/slow routers need more time
        self.retry_count = 5   # number of ARP scan passes for deep scan (increased from 3)
        self.inter_packet_delay = 0.003  # smaller delay for faster scanning

    @staticmethod
    def _get_vendor(mac):
        """
        Resolve device vendor/manufacturer from MAC OUI prefix.
        Uses netaddr's built-in IEEE OUI database.
        Returns empty string if vendor unknown.
        """
        try:
            return EUI(mac).oui.registration().org
        except (NotRegisteredError, IndexError, Exception):
            return ''

    def _spinner_thread(self, message, stop_event):
        """Animated spinner shown while scan is in progress."""
        i = 0
        while not stop_event.is_set():
            elapsed = time.time() - self._scan_start
            frame = self._SPINNER[i % len(self._SPINNER)]
            msg = '\r  {} {}... ({:.1f}s)'.format(frame, message, elapsed)
            sys.stdout.write(msg)
            sys.stdout.flush()
            i += 1
            stop_event.wait(0.1)
        # clear spinner line
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()

    def _read_arp_table(self):
        """
        Read OS ARP cache to discover hosts that are already known.
        Catches devices that responded to previous ARP/ICMP but might
        not respond to our scan packets (phones in power-save, etc).
        Returns dict {mac: ip}.
        """
        hosts = {}

        # Method 1: read /proc/net/arp (Linux)
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3].lower()
                        iface = parts[5]
                        # skip incomplete entries and wrong interface
                        if mac != '00:00:00:00:00:00' and iface == self.interface:
                            hosts[mac] = ip
        except (FileNotFoundError, PermissionError):
            pass

        # Method 2: 'ip neigh' command as fallback
        try:
            output = subprocess.check_output(
                ['ip', 'neigh', 'show', 'dev', self.interface],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    lladdr_idx = parts.index('lladdr')
                    if lladdr_idx + 1 < len(parts):
                        mac = parts[lladdr_idx + 1].lower()
                        state = parts[-1] if len(parts) > lladdr_idx + 2 else ''
                        if mac != '00:00:00:00:00:00' and state not in ('FAILED',):
                            hosts[mac] = ip
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 3: 'arp -an' command as another fallback
        try:
            output = subprocess.check_output(
                ['arp', '-an', '-i', self.interface],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if not line.strip() or '<incomplete>' in line:
                    continue
                # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0
                parts = line.split()
                for j, p in enumerate(parts):
                    if p == 'at' and j + 1 < len(parts) and j >= 1:
                        mac = parts[j + 1].lower()
                        ip_part = parts[j - 1].strip('()')
                        if mac != '00:00:00:00:00:00' and ':' in mac:
                            hosts[mac] = ip_part
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return hosts

    def _passive_arp_sniff(self, duration, discovered):
        """
        Passively sniff ARP traffic for a given duration.
        Catches devices that spontaneously send ARP requests/replies
        (e.g. phones checking gateway, IoT devices announcing themselves).
        Updates the discovered dict in-place.
        """
        def arp_handler(pkt):
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                # capture both source (sender is alive) and target responses
                if arp.psrc and arp.hwsrc:
                    mac = arp.hwsrc.lower()
                    ip = arp.psrc
                    if mac != '00:00:00:00:00:00' and mac != 'ff:ff:ff:ff:ff:ff':
                        discovered[mac] = ip

        try:
            sniff(
                iface=self.interface,
                filter='arp',
                prn=arp_handler,
                timeout=duration,
                store=0
            )
        except Exception:
            pass

    def _mdns_discovery(self, discovered):
        """
        Send mDNS query to discover devices that respond to multicast DNS.
        Many phones, smart TVs, Chromecasts, and IoT devices respond to mDNS.
        This catches devices that may not respond to ARP broadcast.
        """
        try:
            # Build a minimal mDNS query for _services._dns-sd._udp.local
            # Transaction ID = 0, Flags = 0 (standard query), 1 question
            mdns_query = (
                b'\x00\x00'  # Transaction ID
                b'\x00\x00'  # Flags (standard query)
                b'\x00\x01'  # Questions: 1
                b'\x00\x00'  # Answer RRs
                b'\x00\x00'  # Authority RRs
                b'\x00\x00'  # Additional RRs
                # _services._dns-sd._udp.local
                b'\x09_services\x07_dns-sd\x04_udp\x05local\x00'
                b'\x00\x0c'  # Type: PTR
                b'\x00\x01'  # Class: IN
            )

            pkt = (
                Ether(dst='01:00:5e:00:00:fb') /
                IP(dst=self._MDNS_ADDR, ttl=255) /
                UDP(sport=self._MDNS_PORT, dport=self._MDNS_PORT) /
                Raw(load=mdns_query)
            )

            answered, _ = srp(pkt, timeout=3, iface=self.interface, verbose=0, multi=True)

            for sent, received in answered:
                if received.haslayer(Ether):
                    mac = received[Ether].src.lower()
                    if received.haslayer(IP):
                        ip = received[IP].src
                        if mac != 'ff:ff:ff:ff:ff:ff' and mac != '00:00:00:00:00:00':
                            discovered[mac] = ip
        except Exception:
            pass

    def _nbns_discovery(self, discovered):
        """
        Send NetBIOS Name Service broadcast query.
        Windows devices and Samba servers respond to NBNS queries.
        Useful for finding Windows PCs, printers, and NAS devices.
        """
        try:
            # NetBIOS wildcard query: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (encoded *)
            nbns_query = (
                b'\x82\x28'  # Transaction ID
                b'\x01\x10'  # Flags: broadcast query
                b'\x00\x01'  # Questions: 1
                b'\x00\x00'  # Answer RRs
                b'\x00\x00'  # Authority RRs
                b'\x00\x00'  # Additional RRs
                b'\x20'      # Name length
                b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                b'\x00'      # Name terminator
                b'\x00\x21'  # Type: NBSTAT
                b'\x00\x01'  # Class: IN
            )

            pkt = (
                Ether(dst='ff:ff:ff:ff:ff:ff') /
                IP(dst='255.255.255.255') /
                UDP(sport=137, dport=137) /
                Raw(load=nbns_query)
            )

            answered, _ = srp(pkt, timeout=3, iface=self.interface, verbose=0, multi=True)

            for sent, received in answered:
                if received.haslayer(Ether):
                    mac = received[Ether].src.lower()
                    if received.haslayer(IP):
                        ip = received[IP].src
                        if mac != 'ff:ff:ff:ff:ff:ff' and mac != '00:00:00:00:00:00':
                            discovered[mac] = ip
        except Exception:
            pass

    def _tcp_syn_discovery(self, target_ips, discovered):
        """
        Send TCP SYN probes to common ports on all target IPs.
        Some devices (especially IoT, cameras, smart home) don't respond
        to ARP broadcast but DO respond to TCP connections.
        The SYN response reveals their MAC via the Ethernet frame.
        """
        try:
            # Build SYN packets to common ports
            packets = []
            for port in self._TCP_DISCOVERY_PORTS[:4]:  # limit to avoid flooding
                pkts = (
                    Ether(dst='ff:ff:ff:ff:ff:ff') /
                    IP(dst=target_ips) /
                    TCP(dport=port, flags='S')
                )
                if isinstance(pkts, list):
                    packets.extend(pkts)
                else:
                    packets.append(pkts)

            # Send at L3 and capture responses
            for port in self._TCP_DISCOVERY_PORTS[:4]:
                try:
                    answered, _ = sr(
                        IP(dst=target_ips) / TCP(dport=port, flags='S'),
                        timeout=2, iface=self.interface, verbose=0, retry=0
                    )
                    for sent, received in answered:
                        if received.haslayer(IP) and received.haslayer(TCP):
                            ip = received[IP].src
                            # Now resolve MAC from ARP cache (the TCP handshake populated it)
                            if ip not in [v for v in discovered.values()]:
                                mac_from_arp = self._resolve_mac_from_cache(ip)
                                if mac_from_arp:
                                    discovered[mac_from_arp] = ip
                except Exception:
                    pass
        except Exception:
            pass

    def _resolve_mac_from_cache(self, ip):
        """
        Read MAC from OS ARP cache for a specific IP.
        Used after TCP SYN discovery populates the cache.
        """
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].lower()
                        if mac != '00:00:00:00:00:00':
                            return mac
        except (FileNotFoundError, PermissionError):
            pass

        try:
            output = subprocess.check_output(
                ['ip', 'neigh', 'show', ip],
                stderr=subprocess.DEVNULL, timeout=3
            ).decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if 'lladdr' in line:
                    parts = line.split()
                    idx = parts.index('lladdr')
                    if idx + 1 < len(parts):
                        return parts[idx + 1].lower()
        except Exception:
            pass

        return None

    def _dhcp_lease_discovery(self, discovered):
        """
        Read DHCP lease files to discover hosts that have active leases.
        Works on routers and DHCP servers. Useful for finding devices
        that are sleeping but have valid leases.
        """
        lease_files = [
            '/var/lib/dhcp/dhcpd.leases',
            '/var/lib/dhcpd/dhcpd.leases',
            '/tmp/dhcp.leases',
            '/tmp/dnsmasq.leases',
            '/var/lib/misc/dnsmasq.leases',
            '/var/lib/NetworkManager/dnsmasq-*.leases',
        ]

        for lease_file in lease_files:
            try:
                import glob
                for f_path in glob.glob(lease_file):
                    with open(f_path, 'r') as f:
                        content = f.read()
                        # dnsmasq format: timestamp mac ip hostname *
                        for line in content.split('\n'):
                            parts = line.strip().split()
                            if len(parts) >= 4 and ':' in parts[1]:
                                mac = parts[1].lower()
                                ip = parts[2]
                                if mac != '00:00:00:00:00:00':
                                    discovered[mac] = ip
            except Exception:
                pass

    def _ping_sweep(self, target_ips):
        """
        Send ICMP echo requests to wake up sleeping/idle devices.
        Many phones drop into power-save mode and ignore ARP broadcasts,
        but will respond to ICMP or at least update their ARP tables.
        Uses fping (fastest), nmap, or manual pings as fallback.
        """
        ip_list = [str(ip) for ip in target_ips]

        # Try fping first (massively parallel, fastest option)
        try:
            process = subprocess.Popen(
                ['fping', '-a', '-q', '-r', '1', '-t', '800', '-i', '3', '-g',
                 ip_list[0], ip_list[-1]],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            process.communicate(timeout=45)
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()

        # Try nmap ping sweep
        try:
            subprocess.call(
                ['nmap', '-sn', '-n', '--min-rate', '500', '-T4',
                 '--host-timeout', '2s', '{}-{}'.format(ip_list[0], ip_list[-1].split('.')[-1])],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45
            )
            return
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        # Last resort: parallel ping using threads
        def ping_single(ip):
            try:
                subprocess.call(
                    ['ping', '-c', '1', '-W', '1', str(ip)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )
            except (subprocess.TimeoutExpired, Exception):
                pass

        batch_size = 60
        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i + batch_size]
            threads = []
            for ip in batch:
                t = threading.Thread(target=ping_single, args=(ip,), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=4)

    def _arp_scan_pass(self, target_ips, timeout=None):
        """
        Single ARP broadcast scan pass.
        Returns dict {mac: ip} for responding hosts.
        """
        if timeout is None:
            timeout = self.timeout

        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        try:
            answered, _ = srp(packets, timeout=timeout, iface=self.interface,
                              verbose=0, inter=self.inter_packet_delay, retry=0)
        except Exception:
            return {}

        results = {}
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.lower()
            results[mac] = ip

        return results

    def _unicast_arp_probe(self, ip_mac_pairs, timeout=2):
        """
        Send unicast ARP requests to specific IPs using their last-known MACs.
        Some devices (phones in WiFi power-save) ignore broadcast ARP but
        respond to unicast ARP directed at their MAC.
        """
        results = {}
        for ip, mac in ip_mac_pairs:
            try:
                pkt = Ether(dst=mac) / ARP(pdst=ip, op=1)
                answered, _ = srp(pkt, timeout=timeout, iface=self.interface,
                                  verbose=0, retry=0)
                for sent, received in answered:
                    results[received.hwsrc.lower()] = received.psrc
            except Exception:
                pass

        return results

    def scan(self, iprange=None):
        """
        Ultra-deep multi-strategy scan combining 8+ techniques for maximum host discovery.
        Designed to find ALL devices including phones, IoT, cameras on any network.

        Strategy:
          1. Passive ARP sniffing (background) — catches spontaneous ARP traffic
          2. ICMP ping sweep — wakes sleeping devices & populates ARP table
          3. Read OS ARP table — catches already-known hosts
          4. Multiple ARP broadcast passes — with increasing timeouts
          5. mDNS multicast discovery — finds phones, smart TVs, Chromecasts
          6. NetBIOS (NBNS) discovery — finds Windows PCs, printers, NAS
          7. TCP SYN probe — finds devices only responding to TCP connections
          8. Unicast ARP probes — for devices in ARP table but not responding to broadcast
          9. DHCP lease file scan — finds devices with valid leases
         10. Final ARP table read — catches late responders
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        self._scan_start = time.time()

        # start spinner
        stop_event = threading.Event()
        spinner = threading.Thread(
            target=self._spinner_thread,
            args=('ultra-deep scanning {} addresses (8 methods, {} ARP passes)'.format(
                len(target_ips), self.retry_count), stop_event),
            daemon=True
        )
        spinner.start()

        try:
            # Collect all discovered hosts: mac -> ip
            discovered = {}

            # === Phase 1: Start passive ARP sniffing in background ===
            # Runs for the entire scan duration, catches spontaneous traffic
            passive_thread = threading.Thread(
                target=self._passive_arp_sniff,
                args=(30, discovered),  # sniff for up to 30s
                daemon=True
            )
            passive_thread.start()

            # === Phase 2: ICMP ping sweep to wake up sleeping devices ===
            try:
                self._ping_sweep(iprange)
                time.sleep(0.5)  # let devices update their ARP tables
            except Exception:
                pass

            # === Phase 3: Read existing ARP table ===
            arp_hosts = self._read_arp_table()
            discovered.update(arp_hosts)

            # === Phase 4: Multiple ARP broadcast scan passes ===
            for pass_num in range(self.retry_count):
                # increase timeout each pass for slower devices
                timeout = self.timeout + (pass_num * 1.0)
                results = self._arp_scan_pass(target_ips, timeout=timeout)
                discovered.update(results)

                # short delay between passes to let network settle
                if pass_num < self.retry_count - 1:
                    time.sleep(0.2)

            # === Phase 5: mDNS multicast discovery ===
            # Finds phones, smart TVs, Chromecasts, Apple devices, IoT
            try:
                self._mdns_discovery(discovered)
            except Exception:
                pass

            # === Phase 6: NetBIOS (NBNS) discovery ===
            # Finds Windows PCs, printers, NAS devices
            try:
                self._nbns_discovery(discovered)
            except Exception:
                pass

            # === Phase 7: TCP SYN discovery ===
            # Finds devices that only respond to TCP (cameras, IoT hubs)
            try:
                self._tcp_syn_discovery(target_ips, discovered)
            except Exception:
                pass

            # === Phase 8: Unicast ARP for stubborn devices ===
            # Build list of ALL IPs not yet discovered and try unicast
            discovered_ips = set(discovered.values())
            arp_table_fresh = self._read_arp_table()
            unicast_targets = []

            # From ARP table entries not yet in discovered
            for mac, ip in arp_table_fresh.items():
                if ip in target_ips and mac not in discovered:
                    unicast_targets.append((ip, mac))

            # Also try unicast ARP to IPs we found via other methods
            # but don't have MAC for yet
            for mac, ip in list(discovered.items()):
                if mac not in arp_table_fresh:
                    unicast_targets.append((ip, mac))

            if unicast_targets:
                unicast_results = self._unicast_arp_probe(unicast_targets, timeout=3)
                discovered.update(unicast_results)

            # === Phase 9: DHCP lease file scan ===
            try:
                self._dhcp_lease_discovery(discovered)
            except Exception:
                pass

            # === Phase 10: Final ARP table sweep ===
            time.sleep(0.8)
            final_arp = self._read_arp_table()
            for mac, ip in final_arp.items():
                if mac not in discovered and ip in target_ips:
                    discovered[mac] = ip

            # Wait for passive sniffing to complete (if still running)
            passive_thread.join(timeout=2)

        except KeyboardInterrupt:
            stop_event.set()
            spinner.join()
            IO.ok('scan aborted.')
            return []

        # === Filter: only include IPs within our target range ===
        target_ip_set = set(target_ips)
        filtered = {mac: ip for mac, ip in discovered.items()
                    if ip in target_ip_set}

        # === Build host objects ===
        hosts = []
        for mac, ip in filtered.items():
            vendor = self._get_vendor(mac)

            # resolve hostname (with short timeout to avoid blocking)
            name = ''
            try:
                socket.setdefaulttimeout(2)
                host_info = socket.gethostbyaddr(ip)
                name = '' if host_info is None else host_info[0]
            except (socket.herror, socket.timeout, OSError):
                pass
            finally:
                socket.setdefaulttimeout(None)

            host = Host(ip, mac, name)
            host.vendor = vendor
            hosts.append(host)

        # stop spinner
        stop_event.set()
        spinner.join()

        elapsed = time.time() - self._scan_start
        IO.ok('{} hosts discovered in {:.1f}s (ultra-deep scan complete).'.format(len(hosts), elapsed))
        return hosts

    def quick_scan(self, iprange=None):
        """
        Quick single-pass ARP scan for fast results.
        Used by the host watcher for periodic checks.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
        except Exception:
            return []

        hosts = []
        for sent, received in answered:
            host = Host(received.psrc, received.hwsrc, '')
            hosts.append(host)

        return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        """
        Multi-method scan to detect hosts that reconnected with different IPs.
        Combines ARP broadcast + ARP table reading for maximum coverage.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        # ARP broadcast scan
        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        scanned_hosts = []
        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
            for sent, received in answered:
                scanned_hosts.append(Host(received.psrc, received.hwsrc.lower(), ''))
        except Exception:
            pass

        # Also check ARP table for reconnected hosts
        arp_hosts = self._read_arp_table()
        for mac, ip in arp_hosts.items():
            already_found = any(sh.mac.lower() == mac for sh in scanned_hosts)
            if not already_found:
                scanned_hosts.append(Host(ip, mac, ''))

        reconnected_hosts = {}
        for host in hosts:
            for s_host in scanned_hosts:
                if host.mac.lower() == s_host.mac.lower() and host.ip != s_host.ip:
                    s_host.name = host.name
                    s_host.vendor = getattr(host, 'vendor', '')
                    reconnected_hosts[host] = s_host

        return reconnected_hosts