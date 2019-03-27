import netifaces
from scapy.all import ARP, sr1 # pylint: disable=no-name-in-module

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES, BIN_SYSCTL, IP_FORWARD_LOC


def get_default_interface():
    """
    Returns the default IPv4 interface
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][1]


def get_default_gateway():
    """
    Returns the default IPv4 gateway address
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][0]


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface 
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get('netmask')


def get_mac_by_ip(interface, address):
    """
    Resolves hardware address from IP by sending ARP request
    and receiving ARP response
    """
    # ARP packet with operation 1 (who-is)
    packet = ARP(op=1, pdst=address)
    response = sr1(packet, timeout=3, verbose=0, iface=interface)

    if response is not None:
        return response.hwsrc


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    return interface in netifaces.interfaces()


def flush_network_settings(interface):
    """
    Flushes all iptable rules and traffic control entries
    related to the given interface
    """
    # reset default policy
    shell.execute_suppressed(f'{BIN_IPTABLES} -P INPUT ACCEPT')
    shell.execute_suppressed(f'{BIN_IPTABLES} -P OUTPUT ACCEPT')
    shell.execute_suppressed(f'{BIN_IPTABLES} -P FORWARD ACCEPT')

    # flush all chains in all tables (including user-defined)
    shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -t nat -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -X')

    # delete root qdisc for given interface
    shell.execute_suppressed(f'{BIN_TC} qdisc del dev {interface} root')


def validate_netrate_string(string):
    """
    Checks if a given net rate string is valid, e.g. 100kbit
    """
    number = 0  # rate number
    offset = 0  # string offset

    for c in string:
        if c.isdigit():
            number = number * 10 + int(c)
            offset += 1
        else:
            break

    # if offset = 0, number is missing
    return offset > 0 and string[offset:] in ('bit', 'kbit', 'mbit', 'gbit', 'tbit')


def create_qdisc_root(interface):
    """
    Creates a root htb qdisc in traffic control for a given interface
    """
    return shell.execute_suppressed(f'{BIN_TC} qdisc add dev {interface} root handle 1:0 htb') == 0


def delete_qdisc_root(interface):
    return shell.execute_suppressed(f'{BIN_TC} qdisc del dev {interface} root handle 1:0 htb')


def enable_ip_forwarding():
    return shell.execute_suppressed(f'{BIN_SYSCTL} -w {IP_FORWARD_LOC}=1') == 0


def disable_ip_forwarding():
    return shell.execute_suppressed(f'{BIN_SYSCTL} -w {IP_FORWARD_LOC}=0') == 0