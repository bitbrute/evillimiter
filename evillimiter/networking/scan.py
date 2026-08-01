import os
import re
import sys
import socket
from tqdm import tqdm
from netaddr import IPAddress
from scapy.all import srp1, ARP, Ether # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from evillimiter.console.io import IO


def resolve_hostname(ip, mac=None):
    """
    Resolves LAN hostnames using a multi-protocol resolution chain via IP and MAC:
    1. Direct MAC lookup in DHCP lease files & system log files (/var/lib/misc/dnsmasq.leases, /etc/hosts)
    2. NetBIOS Node Status Query (UDP 137)
    3. LLMNR Query (UDP 5355)
    4. Multicast DNS (mDNS) PTR Query (UDP 5353)
    5. SSDP / UPnP M-SEARCH Device Name Query (UDP 1900)
    6. Standard Reverse DNS (socket.gethostbyaddr)
    """
    # 1. Direct MAC-based DHCP lease file lookup
    if mac:
        mac_lower = mac.lower()
        lease_files = [
            '/var/lib/misc/dnsmasq.leases',
            '/var/lib/dhcp/dhcpd.leases',
            '/var/lib/dhcpcd/dhcpcd.leases',
            '/var/log/syslog',
            '/var/log/messages',
            '/etc/hosts'
        ]
        for lfile in lease_files:
            if os.path.exists(lfile):
                try:
                    with open(lfile, 'r') as f:
                        for line in f:
                            if mac_lower in line.lower() or ip in line:
                                parts = line.strip().split()
                                for p in parts:
                                    if p.lower() != mac_lower and p != ip and not p.startswith('#') and ':' not in p and len(p) > 2 and p != '*':
                                        if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', p) and not re.match(r'^\d+$', p):
                                            return p
                except Exception:
                    pass

    # 2. NetBIOS Name Query (UDP 137)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.3)
        nbns_req = b'\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
        sock.sendto(nbns_req, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            if num_names > 0:
                name_bytes = data[57:57+15]
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if name:
                    return name
    except Exception:
        pass

    # 3. LLMNR Query (UDP 5355 - Windows host resolution)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.3)
        parts = ip.split('.')
        arpa = '.'.join(reversed(parts)) + '.in-addr.arpa'
        llmnr_req = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in arpa.split('.'):
            llmnr_req += bytes([len(part)]) + part.encode('ascii')
        llmnr_req += b'\x00\x00\x0c\x00\x01'
        sock.sendto(llmnr_req, (ip, 5355))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 12:
            matches = re.findall(rb'[a-zA-Z0-9\-]{3,}', data[12:])
            for match in matches:
                name_str = match.decode('ascii', errors='ignore')
                if name_str.lower() not in ('arpa', 'in-addr', 'local', 'domain', 'dns'):
                    return name_str
    except Exception:
        pass

    # 4. mDNS PTR Query (UDP 5353)
    try:
        parts = ip.split('.')
        arpa = '.'.join(reversed(parts)) + '.in-addr.arpa'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.3)

        query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in arpa.split('.'):
            query += bytes([len(part)]) + part.encode('ascii')
        query += b'\x00\x00\x0c\x00\x01'

        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 12:
            matches = re.findall(rb'[a-zA-Z0-9\-]{3,}', data[12:])
            for match in matches:
                name_str = match.decode('ascii', errors='ignore')
                if name_str.lower() not in ('arpa', 'in-addr', 'local', 'domain', 'dns'):
                    return name_str
    except Exception:
        pass

    # 5. SSDP / UPnP M-SEARCH Query (UDP 1900 - Smart TVs, Printers, IoT)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        ssdp_req = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 1\r\n'
            'ST: ssdp:all\r\n\r\n'
        ).encode('ascii')
        sock.sendto(ssdp_req, (ip, 1900))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if b'LOCATION:' in data or b'SERVER:' in data:
            match = re.search(rb'SERVER:\s*([^\r\n]+)', data, re.IGNORECASE)
            if match:
                server_name = match.group(1).decode('ascii', errors='ignore').strip()
                if server_name:
                    return server_name.split('/')[0]
    except Exception:
        pass

    # 6. Standard Reverse DNS
    try:
        host_info = socket.gethostbyaddr(ip)
        if host_info and host_info[0]:
            name = host_info[0]
            if name.endswith('.local'):
                name = name[:-6]
            return name
    except Exception:
        pass

    return ''


OUI_VENDORS = {
    # Apple
    '00:05:02': 'Apple', '00:0a:95': 'Apple', '00:0d:93': 'Apple', '00:10:fa': 'Apple',
    '00:11:24': 'Apple', '00:14:51': 'Apple', '00:16:cb': 'Apple', '00:17:f2': 'Apple',
    '00:19:e3': 'Apple', '00:1b:63': 'Apple', '00:1c:b3': 'Apple', '00:1d:4f': 'Apple',
    '00:1e:52': 'Apple', '00:1f:5b': 'Apple', '00:1f:f3': 'Apple', '00:21:e9': 'Apple',
    '00:22:41': 'Apple', '00:23:12': 'Apple', '00:23:32': 'Apple', '00:23:6c': 'Apple',
    '00:24:36': 'Apple', '00:25:00': 'Apple', '00:25:4b': 'Apple', '00:25:bc': 'Apple',
    # Samsung
    '00:00:f0': 'Samsung', '00:02:78': 'Samsung', '00:07:ab': 'Samsung', '00:09:18': 'Samsung',
    '00:0d:ae': 'Samsung', '00:12:fb': 'Samsung', '00:13:77': 'Samsung', '00:15:99': 'Samsung',
    '00:21:d2': 'Samsung', '00:23:d7': 'Samsung', '00:24:e2': 'Samsung', '00:26:37': 'Samsung',
    # Oppo
    '2c:57:31': 'Oppo', '94:f1:28': 'Oppo', 'e8:bb:a8': 'Oppo', '00:9e:c8': 'Oppo',
    '54:21:ad': 'Oppo', '84:2e:27': 'Oppo', '88:28:b3': 'Oppo', 'a0:86:c6': 'Oppo',
    'c8:d9:d2': 'Oppo', 'e4:a7:c5': 'Oppo', 'f8:84:f2': 'Oppo', '6c:c4:d3': 'Oppo',
    '80:48:26': 'Oppo', '3c:a5:81': 'Oppo', '48:74:12': 'Oppo',
    # Realme
    '04:d6:aa': 'Realme', '14:38:70': 'Realme', '28:2c:b2': 'Realme', '34:1c:f0': 'Realme',
    '44:bb:3b': 'Realme', '5c:e9:1e': 'Realme', '80:c0:ca': 'Realme', '8c:66:35': 'Realme',
    '94:0d:61': 'Realme', 'a0:77:80': 'Realme', 'ac:b5:7d': 'Realme', 'b4:8c:9d': 'Realme',
    'c0:94:ad': 'Realme', 'e8:76:8b': 'Realme', 'f4:bd:9e': 'Realme',
    # Vivo
    'a8:b4:58': 'Vivo', 'b8:98:f7': 'Vivo', '04:cf:4b': 'Vivo', '28:22:d3': 'Vivo',
    '60:73:bc': 'Vivo', 'a0:47:d7': 'Vivo', 'd8:80:88': 'Vivo', 'f4:b3:01': 'Vivo',
    '18:78:22': 'Vivo', '74:a7:8e': 'Vivo', '84:89:12': 'Vivo',
    # OnePlus
    'c0:ee:fb': 'OnePlus', '94:65:2d': 'OnePlus', 'b0:f1:ec': 'OnePlus', 'ec:2c:e2': 'OnePlus',
    'a4:c7:de': 'OnePlus', '64:a2:f9': 'OnePlus',
    # Honor
    '60:2c:14': 'Honor', 'ec:13:db': 'Honor', 'bc:d1:77': 'Honor', '80:45:ad': 'Honor',
    '08:86:3b': 'Honor',
    # Transsion / Infinix / Tecno / Itel
    '04:84:5d': 'Infinix', '10:2c:6b': 'Tecno', '28:44:63': 'Infinix', '4c:b2:0c': 'Tecno',
    '90:90:5e': 'Infinix', 'b0:41:8f': 'Tecno', 'd8:f1:5b': 'Infinix', 'e0:11:75': 'Tecno',
    # Xiaomi / Redmi / POCO
    'a4:4e:31': 'Xiaomi', '64:09:80': 'Xiaomi', '34:80:b3': 'Xiaomi', 'fc:7c:02': 'Xiaomi',
    '18:59:36': 'Xiaomi', '28:6c:07': 'Xiaomi', '58:44:98': 'Xiaomi', '7c:1d:d9': 'Xiaomi',
    '8c:be:be': 'Xiaomi', 'd4:61:9d': 'Xiaomi', 'f4:60:77': 'Xiaomi',
    # Huawei
    '70:89:cc': 'Huawei', '00:1e:10': 'Huawei', '00:e0:fc': 'Huawei', '24:69:a5': 'Huawei',
    # Motorola & Lenovo
    '00:0a:28': 'Motorola', '00:0c:e5': 'Motorola', '14:30:c6': 'Motorola', '78:4b:87': 'Motorola',
    'e0:75:0a': 'Motorola', '00:12:fe': 'Lenovo', '08:3e:8e': 'Lenovo', '60:99:d1': 'Lenovo',
    'a4:8c:db': 'Lenovo', 'e4:b3:18': 'Lenovo',
    # Asus & Acer & Razer
    '00:0e:a6': 'Asus', '00:11:d8': 'Asus', '00:18:f3': 'Asus', '04:d9:f5': 'Asus',
    '10:bf:48': 'Asus', '2c:4d:54': 'Asus', '30:85:a9': 'Asus', '74:d0:2b': 'Asus',
    'ac:22:0b': 'Asus', 'f8:32:e4': 'Asus',
    # Google & Microsoft & Cisco
    '00:00:0c': 'Cisco', '00:01:42': 'Cisco', '00:0f:ea': 'Microsoft', '00:15:5d': 'Microsoft',
    '00:1a:80': 'Google', '00:1a:11': 'Google', '3c:5a:b4': 'Google', 'f4:f5:d8': 'Google',
    '24:a0:74': 'Amazon', '68:37:e9': 'Amazon', 'a4:e9:75': 'Amazon', '74:75:48': 'Amazon',
    '44:65:0d': 'Amazon', 'fc:a1:83': 'Amazon',
    # Networking / Routers (TP-Link, Netgear, D-Link, Tenda, Mercusys)
    '50:ec:50': 'TP-Link', 'f8:1a:67': 'TP-Link', 'c0:25:e9': 'TP-Link', 'e8:48:b8': 'TP-Link',
    '18:d6:c7': 'TP-Link', '64:70:02': 'TP-Link', 'ec:08:6b': 'TP-Link', '70:ee:50': 'Netgear',
    '00:14:6c': 'Netgear', '00:1f:33': 'Netgear', '00:24:b2': 'Netgear', '00:26:f2': 'Netgear',
    '00:05:5d': 'D-Link', '00:0d:88': 'D-Link', '00:15:e9': 'D-Link', '00:17:9a': 'D-Link',
    '00:b0:0c': 'Tenda', '04:95:e6': 'Tenda', '50:2b:73': 'Tenda', '98:3b:8f': 'Tenda',
    '48:22:54': 'Mercusys', '70:4f:57': 'Mercusys', '88:25:2c': 'Mercusys', '90:de:f7': 'Mercusys',
    '98:da:c4': 'Realtek', '00:e0:4c': 'Realtek', '00:1b:21': 'Intel', '00:1c:c0': 'Intel',
    '00:21:6b': 'Intel', '00:23:14': 'Intel', '00:24:d7': 'Intel',
    # IoT / Microcontrollers (Espressif, Raspberry Pi)
    '18:fe:34': 'ESP32-IoT', '24:0a:c4': 'ESP32-IoT', '24:62:ab': 'ESP32-IoT', '30:ae:a4': 'ESP32-IoT',
    '40:22:d8': 'ESP32-IoT', '48:3f:da': 'ESP32-IoT', '54:5a:a6': 'ESP32-IoT', '68:c6:3a': 'ESP32-IoT',
    '70:03:9f': 'ESP32-IoT', '7c:df:a1': 'ESP32-IoT', '84:0d:8e': 'ESP32-IoT', '84:f3:eb': 'ESP32-IoT',
    '28:cd:c1': 'RaspberryPi', 'b8:27:eb': 'RaspberryPi', 'dc:a6:32': 'RaspberryPi', 'e4:5f:01': 'RaspberryPi',
    # Gaming & Entertainment (Sony, Nintendo, LG, Snom)
    'e0:91:53': 'Sony', '00:01:4a': 'Sony', '00:04:1f': 'Sony', '00:13:15': 'Sony',
    '00:1f:a7': 'Sony', '00:09:bf': 'Nintendo', '00:17:ab': 'Nintendo', '00:1b:ea': 'Nintendo',
    '00:1f:32': 'Nintendo', '00:22:d7': 'Nintendo', '00:23:cc': 'Nintendo', '00:08:ca': 'LG',
    '00:13:e0': 'LG', '00:19:a1': 'LG', '00:1c:62': 'LG', '00:1e:b2': 'LG', '00:04:13': 'Snom'
}


def _load_system_oui_database():
    """
    Parses system-installed OUI databases (Wireshark manuf, Nmap mac-prefixes, IEEE oui.txt)
    """
    db = {}
    paths = [
        '/usr/share/wireshark/manuf',
        '/etc/manuf',
        '/usr/share/nmap/nmap-mac-prefixes',
        '/usr/share/ieee-data/oui.txt',
        '/var/lib/ieee-data/oui.txt'
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            mac_prefix = parts[0].lower().replace('-', ':')
                            if len(mac_prefix) == 8 and mac_prefix.count(':') == 2:
                                vendor_name = parts[1] if len(parts) == 2 else ' '.join(parts[1:])
                                db[mac_prefix] = vendor_name.split('#')[0].strip()
            except Exception:
                pass
    return db


SYSTEM_OUI_DB = _load_system_oui_database()
_DYNAMIC_VENDOR_CACHE = {}


def _get_vendor_by_mac(mac):
    if not mac or len(mac) < 8:
        return ''
    prefix = mac.lower()[:8]

    # 1. System-installed Wireshark / Nmap / IEEE OUI Database
    if prefix in SYSTEM_OUI_DB:
        return f"{SYSTEM_OUI_DB[prefix]}-Device"

    # 2. Built-in Comprehensive OUI Table
    if prefix in OUI_VENDORS:
        return f"{OUI_VENDORS[prefix]}-Device"

    # 3. Memory cache for dynamically resolved vendors
    if prefix in _DYNAMIC_VENDOR_CACHE:
        return _DYNAMIC_VENDOR_CACHE[prefix]

    # 4. Online API Fallback (maclookup.app / macvendors.com)
    try:
        import urllib.request
        req = urllib.request.Request(
            f'https://api.maclookup.app/v2/macs/{mac}/company/name',
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=0.4) as response:
            vendor_name = response.read().decode('utf-8', errors='ignore').strip()
            if vendor_name and 'error' not in vendor_name.lower() and len(vendor_name) < 30:
                result_str = f"{vendor_name}-Device"
                _DYNAMIC_VENDOR_CACHE[prefix] = result_str
                return result_str
    except Exception:
        pass

    return ''


def _parse_kernel_arp_cache():
    """
    Parses /proc/net/arp to retrieve system cached IP-to-MAC resolutions
    """
    arp_map = {}
    try:
        if os.path.exists('/proc/net/arp'):
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac != '00:00:00:00:00:00' and re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                            arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange

        self.max_workers = 75   # max. amount of threads
        self.retries = 1        # ARP retry (increased for Wi-Fi reliability)
        self.timeout = 1.2      # tuned timeout per probe

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

            scanned_mac_map = {s_host.mac: s_host for s_host in scanned_hosts}
            reconnected_hosts = {}
            for host in hosts:
                s_host = scanned_mac_map.get(host.mac)
                if s_host and host.ip != s_host.ip:
                    s_host.name = host.name
                    reconnected_hosts[host] = s_host
            
            return reconnected_hosts

    def _sweep(self, ip):
        """
        Multi-probe sweep:
        1. Direct Layer-2 ARP request (srp1)
        2. Kernel ARP cache check (/proc/net/arp)
        3. Lightweight UDP/ICMP probe fallback
        """
        mac = None

        # 1. ARP Request
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
        answer = srp1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
        
        if answer is not None:
            mac = answer.hwsrc
        else:
            # 2. Check kernel ARP cache
            arp_cache = _parse_kernel_arp_cache()
            if ip in arp_cache:
                mac = arp_cache[ip]
            else:
                # 3. Fallback UDP probe to trigger kernel ARP table resolution
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.15)
                    sock.sendto(b'\x00', (ip, 80))
                    sock.close()
                except Exception:
                    pass

                arp_cache = _parse_kernel_arp_cache()
                if ip in arp_cache:
                    mac = arp_cache[ip]

        if mac is not None:
            name = resolve_hostname(ip, mac)
            if not name:
                name = _get_vendor_by_mac(mac)
            return Host(ip, mac, name)