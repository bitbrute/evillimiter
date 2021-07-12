import sys
import socket
from tqdm import tqdm
from netaddr import IPAddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
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

    def scan(self, iprange=None):
        self._resolve_names = True

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            iterator = tqdm(
                iterable=executor.map(self._sweep, iprange),
                total=len(iprange),
                ncols=45,
                bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}'
            )

            try:
                for host in iterator:
                    if host is not None:
                        try:
                            host_info = socket.gethostbyaddr(host.ip)
                            name = '' if host_info is None else host_info[0]
                            host.name = name
                        except socket.herror:
                            pass

                        hosts.append(host)
            except KeyboardInterrupt:
                iterator.close()
                IO.ok('aborted. waiting for shutdown...')

            return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            scanned_hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            for host in executor.map(self._sweep, iprange):
                if host is not None:
                    scanned_hosts.append(host)

            reconnected_hosts = {}
            for host in hosts:
                for s_host in scanned_hosts:
                    if host.mac == s_host.mac and host.ip != s_host.ip:
                        s_host.name = host.name
                        reconnected_hosts[host] = s_host
            
            return reconnected_hosts

    def _sweep(self, ip):
        """
        Sends ARP packet and listens for answer,
        if present the host is online
        """
        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
        
        if answer is not None:
            return Host(ip, answer.hwsrc, '')
