import sys
import socket
from tqdm import tqdm
from netaddr import IPAddress
from scapy.all import sr1, ARP # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO
        

class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange

        self.max_workers = 75   # max. amount of threads
        self.retries = 0        # ARP retry
        self.timeout = 2.5      # time in s to wait for an answer

    def scan(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            hosts = []
            iterator = tqdm(
                iterable=executor.map(self._sweep, self.iprange),
                total=len(self.iprange),
                ncols=45,
                bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}'
            )

            try:
                for host in iterator:
                    if host is not None:
                        hosts.append(host)
            except KeyboardInterrupt:
                iterator.close()
                IO.ok('aborted. waiting for shutdown...')

            return hosts

    def _sweep(self, ip):
        """
        Sends ARP packet and listens for answer,
        if present the host is online
        """
        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
        
        if answer is not None:
            mac = answer.hwsrc
            name = None

            try:
                host_info = socket.gethostbyaddr(ip)
                name = None if host_info is None else host_info[0]
            except socket.herror:
                pass

            return Host(ip, mac, name)