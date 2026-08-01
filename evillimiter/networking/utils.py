import re
try:
    import netifaces
except ImportError:
    netifaces = None

from scapy.all import ARP, Ether, srp1 # pylint: disable=no-name-in-module

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES, BIN_SYSCTL, IP_FORWARD_LOC, BROADCAST


def _parse_proc_net_route():
    """
    Parses /proc/net/route to find default gateway and interface
    """
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == '00000000':
                    interface = fields[0]
                    gateway_hex = fields[2]
                    ip_bytes = [int(gateway_hex[i:i+2], 16) for i in (6, 4, 2, 0)]
                    gateway_ip = '.'.join(str(b) for b in ip_bytes)
                    return gateway_ip, interface
    except Exception:
        pass
    return None, None


def get_default_interface():
    """
    Returns the default IPv4 interface
    """
    if netifaces is not None:
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][1]
        except Exception:
            pass

    _, interface = _parse_proc_net_route()
    return interface


def get_default_gateway():
    """
    Returns the default IPv4 gateway address
    """
    if netifaces is not None:
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][0]
        except Exception:
            pass

    gateway_ip, _ = _parse_proc_net_route()
    return gateway_ip


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface 
    """
    if netifaces is not None:
        try:
            ifaddrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in ifaddrs:
                return ifaddrs[netifaces.AF_INET][0].get('netmask')
        except Exception:
            pass

    try:
        import socket
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netmask = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24])
        return netmask
    except Exception:
        return '255.255.255.0'


def get_mac_by_ip(interface, address):
    """
    Resolves hardware address from IP by sending ARP request
    and receiving ARP response
    """
    # ARP packet wrapped in Layer 2 Ethernet frame
    packet = Ether(dst=BROADCAST) / ARP(op=1, pdst=address)
    response = srp1(packet, timeout=3, verbose=0, iface=interface)

    if response is not None:
        return response.hwsrc


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    if netifaces is not None:
        try:
            return interface in netifaces.interfaces()
        except Exception:
            pass

    return os.path.exists('/sys/class/net/{}'.format(interface))


def flush_network_settings(interface):
    """
    Flushes all iptable rules and traffic control entries
    related to the given interface
    """
    # reset default policy
    shell.execute_suppressed('{} -P INPUT ACCEPT'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -P OUTPUT ACCEPT'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -P FORWARD ACCEPT'.format(BIN_IPTABLES))

    # flush all chains in all tables (including user-defined)
    shell.execute_suppressed('{} -t mangle -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -t nat -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -X'.format(BIN_IPTABLES))

    # delete root qdisc for given interface
    shell.execute_suppressed('{} qdisc del dev {} root'.format(BIN_TC, interface))


def validate_ip_address(ip):
    return re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', ip) is not None


def validate_mac_address(mac):
    return re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac) is not None


def create_qdisc_root(interface):
    """
    Creates a root htb qdisc in traffic control for a given interface with a default fallback class
    """
    res = shell.execute_suppressed('{} qdisc add dev {} root handle 1:0 htb default 9999'.format(BIN_TC, interface)) == 0
    if res:
        shell.execute_suppressed('{} class add dev {} parent 1:0 classid 1:9999 htb rate 1gbit'.format(BIN_TC, interface))
    return res


def delete_qdisc_root(interface):
    return shell.execute_suppressed('{} qdisc del dev {} root handle 1:0 htb'.format(BIN_TC, interface))


def enable_ip_forwarding(interface=None, gateway_ip=None, gateway_mac=None):
    try:
        # Enable forwarding globally and per interface
        for loc in [
            '/proc/sys/net/ipv4/ip_forward',
            '/proc/sys/net/ipv4/conf/all/forwarding',
            '/proc/sys/net/ipv4/conf/default/forwarding'
        ]:
            if os.path.exists(loc):
                try:
                    with open(loc, 'w') as f:
                        f.write('1\n')
                except Exception:
                    pass

        if interface and os.path.exists('/proc/sys/net/ipv4/conf/{}/forwarding'.format(interface)):
            try:
                with open('/proc/sys/net/ipv4/conf/{}/forwarding'.format(interface), 'w') as f:
                    f.write('1\n')
            except Exception:
                pass

        # Disable reverse path filtering (rp_filter) and ICMP redirects to prevent kernel ICMP net unreachable drops
        sysctl_nodes = [
            '/proc/sys/net/ipv4/conf/all/rp_filter',
            '/proc/sys/net/ipv4/conf/default/rp_filter',
            '/proc/sys/net/ipv4/conf/all/send_redirects',
            '/proc/sys/net/ipv4/conf/default/send_redirects',
            '/proc/sys/net/ipv4/conf/all/accept_redirects',
            '/proc/sys/net/ipv4/conf/default/accept_redirects'
        ]
        if interface:
            sysctl_nodes.extend([
                '/proc/sys/net/ipv4/conf/{}/rp_filter'.format(interface),
                '/proc/sys/net/ipv4/conf/{}/send_redirects'.format(interface),
                '/proc/sys/net/ipv4/conf/{}/accept_redirects'.format(interface)
            ])

        for node in sysctl_nodes:
            if os.path.exists(node):
                try:
                    with open(node, 'w') as f:
                        f.write('0\n')
                except Exception:
                    pass

        # Ensure default FORWARD chain policy is ACCEPT across all tables
        shell.execute_suppressed('{} -P FORWARD ACCEPT'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -t raw -F'.format(BIN_IPTABLES))

        # Suppress ICMP Type 3 (Destination Unreachable) error messages generated by host/kernel
        shell.execute_suppressed('{} -t filter -I OUTPUT 1 -p icmp --icmp-type 3 -j DROP'.format(BIN_IPTABLES))
        shell.execute_suppressed('{} -t filter -I FORWARD 1 -p icmp --icmp-type 3 -j DROP'.format(BIN_IPTABLES))

        # Lock static ARP entry for Gateway if provided so forwarding never loses Gateway route
        if interface and gateway_ip and gateway_mac:
            shell.execute_suppressed('{} neigh replace {} lladdr {} dev {} nud reachable'.format(BIN_IP, gateway_ip, gateway_mac, interface))

        return True
    except Exception:
        return shell.execute_suppressed('{} -w {}=1'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


from evillimiter.common.globals import BIN_TC, BIN_IPTABLES, BIN_SYSCTL, BIN_CONNTRACK, BIN_IP, IP_FORWARD_LOC, BROADCAST


def setup_ifb(interface, ifb_dev='ifb0'):
    """
    Sets up IFB (Intermediate Functional Block) virtual device for true ingress shaping
    """
    try:
        # Load ifb kernel module
        shell.execute_suppressed('modprobe ifb numifbs=1')
        shell.execute_suppressed('{} link set dev {} up'.format(BIN_IP, ifb_dev))
        
        # Add ingress qdisc on physical interface if not present
        shell.execute_suppressed('{} qdisc add dev {} handle ffff: ingress'.format(BIN_TC, interface))
        
        # Create HTB root on IFB device (target traffic will be selectively redirected to ifb0 per host)
        create_qdisc_root(ifb_dev)
        return True
    except Exception:
        return False


def add_ifb_redirect(interface, target_ip, prio, ifb_dev='ifb0'):
    """
    Selectively redirects incoming ingress traffic for target_ip on physical interface to IFB device
    """
    shell.execute_suppressed(
        '{} filter add dev {} parent ffff: protocol ip prio {} u32 match ip dst {}/32 action mirred egress redirect dev {}'.format(
            BIN_TC, interface, prio, target_ip, ifb_dev
        )
    )


def del_ifb_redirect(interface, prio):
    """
    Deletes selective IFB redirect filter for a given priority ID on physical interface
    """
    shell.execute_suppressed('{} filter del dev {} parent ffff: prio {}'.format(BIN_TC, interface, prio))


def delete_ifb(interface, ifb_dev='ifb0'):
    """
    Deletes IFB ingress redirection and root qdisc
    """
    shell.execute_suppressed('{} qdisc del dev {} parent ffff: ingress'.format(BIN_TC, interface))
    shell.execute_suppressed('{} qdisc del dev {} root'.format(BIN_TC, ifb_dev))
    shell.execute_suppressed('{} link set dev {} down'.format(BIN_IP, ifb_dev))


def flush_conntrack(ip_address):
    """
    Flushes connection tracking table entries for a specific IP address to immediately enforce block/limit rules on active TCP sessions
    """
    if BIN_CONNTRACK and not str(BIN_CONNTRACK).startswith('missing'):
        shell.execute_suppressed('{} -D -s {}'.format(BIN_CONNTRACK, ip_address))
        shell.execute_suppressed('{} -D -d {}'.format(BIN_CONNTRACK, ip_address))


def disable_ip_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0\n')
        return True
    except Exception:
        return shell.execute_suppressed('{} -w {}=0'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def enable_stealth_mode(interface):
    """
    Enables stealth mode: suppresses local ICMP leaks and inbound LAN service probes (mDNS, NetBIOS, LLMNR, SSDP)
    """
    try:
        # Drop outgoing/incoming ICMP packets from/to local host on physical interface
        shell.execute_suppressed('{} -t filter -I INPUT 1 -i {} -p icmp -j DROP'.format(BIN_IPTABLES, interface))
        shell.execute_suppressed('{} -t filter -I OUTPUT 1 -o {} -p icmp -j DROP'.format(BIN_IPTABLES, interface))

        # Drop inbound service probes on local IP
        for port in (137, 138, 139, 5353, 5355, 1900):
            shell.execute_suppressed('{} -t filter -I INPUT 1 -i {} -p udp --dport {} -j DROP'.format(BIN_IPTABLES, interface, port))
        return True
    except Exception:
        return False


def disable_stealth_mode(interface):
    """
    Tears down stealth mode iptables rules
    """
    try:
        shell.execute_suppressed('{} -t filter -D INPUT -i {} -p icmp -j DROP'.format(BIN_IPTABLES, interface))
        shell.execute_suppressed('{} -t filter -D OUTPUT -o {} -p icmp -j DROP'.format(BIN_IPTABLES, interface))

        for port in (137, 138, 139, 5353, 5355, 1900):
            shell.execute_suppressed('{} -t filter -D INPUT -i {} -p udp --dport {} -j DROP'.format(BIN_IPTABLES, interface, port))
        return True
    except Exception:
        return False


class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8


class BitRate(object):
    _UNITS = ['bit', 'kbit', 'mbit', 'gbit']
    _UNIT_MULTIPLIERS = {'bit': 1, 'kbit': 1000, 'mbit': 1000**2, 'gbit': 1000**3}

    def __init__(self, rate=0):
        self.rate = rate

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        r = float(self.rate)

        while r >= 1000 and counter < len(BitRate._UNITS) - 1:
            if r % 1000 != 0 and r / 1000 < 1000:
                break
            r /= 1000
            counter += 1

        if r >= 1000 and counter == len(BitRate._UNITS) - 1:
            raise Exception('Bitrate limit exceeded')

        return '{}{}'.format(int(r), BitRate._UNITS[counter])

    def __mul__(self, other):
        if isinstance(other, BitRate):
            return BitRate(int(self.rate * other.rate))
        return BitRate(int(self.rate * other))

    def fmt(self, fmt):
        string = self.__str__()
        match = re.match(r'^(\d+)(.*)$', string)
        if match:
            num, unit = match.groups()
            return '{}{}'.format(fmt % int(num), unit)
        return string

    @classmethod
    def from_rate_string(cls, rate_string):
        return cls(BitRate._bit_value(rate_string))

    @staticmethod
    def _bit_value(rate_string):
        match = re.match(r'^(\d+)\s*([a-zA-Z]+)?$', rate_string.strip())
        if not match:
            raise Exception('Invalid bitrate')

        number_str, unit_str = match.groups()
        number = int(number_str)
        unit = (unit_str or 'bit').lower()

        if unit in BitRate._UNIT_MULTIPLIERS:
            return number * BitRate._UNIT_MULTIPLIERS[unit]
        raise Exception('Invalid bitrate')


class ByteValue(object):
    _UNITS = ['b', 'kb', 'mb', 'gb', 'tb']
    _UNIT_MULTIPLIERS = {'b': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3, 'tb': 1024**4}

    def __init__(self, value=0):
        self.value = value

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        v = self.value

        while v >= 1024 and counter < len(ByteValue._UNITS) - 1:
            v /= 1024
            counter += 1

        if v >= 1024:
            raise Exception('Byte value limit exceeded')

        return '{}{}'.format(int(v), ByteValue._UNITS[counter])

    def __int__(self):
        return self.value

    def __add__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value + other.value))
        return ByteValue(int(self.value + other))

    def __sub__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value - other.value))
        return ByteValue(int(self.value - other))

    def __mul__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value * other.value))
        return ByteValue(int(self.value * other))

    def __ge__(self, other):
        if isinstance(other, ByteValue):
            return self.value >= other.value
        return self.value >= other

    def fmt(self, fmt):
        string = self.__str__()
        match = re.match(r'^(\d+)(.*)$', string)
        if match:
            num, unit = match.groups()
            return '{}{}'.format(fmt % int(num), unit)
        return string

    @classmethod
    def from_byte_string(cls, byte_string):
        return cls(ByteValue._byte_value(byte_string))

    @staticmethod
    def _byte_value(byte_string):
        match = re.match(r'^(\d+)\s*([a-zA-Z]+)?$', byte_string.strip())
        if not match:
            raise Exception('Invalid byte string')

        number_str, unit_str = match.groups()
        number = int(number_str)
        unit = (unit_str or 'b').lower()

        if unit in ByteValue._UNIT_MULTIPLIERS:
            return number * ByteValue._UNIT_MULTIPLIERS[unit]
        raise Exception('Invalid byte string')