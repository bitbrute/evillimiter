import sys
import os
import os.path
import re
import argparse
import platform
import collections

# Fix sys.path if run directly from inside the package directory
curr_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(os.path.join(curr_dir, '..'))

if sys.path and os.path.abspath(sys.path[0]) == curr_dir:
    sys.path.pop(0)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import evillimiter.networking.utils as netutils
from evillimiter.menus.main_menu import MainMenu
from evillimiter.console.banner import get_main_banner
from evillimiter.console.io import IO


InitialArguments = collections.namedtuple('InitialArguments', 'interface, gateway_ip, netmask, gateway_mac, stealth')


def get_init_content():
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), '__init__.py'), 'r') as f:
        return f.read()


def get_version():
    version_match = re.search(r'^__version__ = [\'"](\d\.\d\.\d)[\'"]', get_init_content(), re.M)
    if version_match:
        return version_match.group(1)
    
    raise RuntimeError('Unable to locate version string.')


def get_description():
    desc_match = re.search(r'^__description__ = [\'"]((.)*)[\'"]', get_init_content(), re.M)
    if desc_match:
        return desc_match.group(1)
    
    raise RuntimeError('Unable to locate description string.')


def is_privileged():
    return os.geteuid() == 0


def is_linux():
    return platform.system() == 'Linux'


def parse_arguments():
    """
    Parses the main command-line arguments (sys.argv)
    using argparse
    """
    parser = argparse.ArgumentParser(description=get_description())
    parser.add_argument('-i', '--interface', help='network interface connected to the target network. automatically resolved if not specified.')
    parser.add_argument('-g', '--gateway-ip', dest='gateway_ip', help='default gateway ip address. automatically resolved if not specified.')
    parser.add_argument('-m', '--gateway-mac', dest='gateway_mac', help='gateway mac address. automatically resolved if not specified.')
    parser.add_argument('-n', '--netmask', help='netmask for the network. automatically resolved if not specified.')
    parser.add_argument('-f', '--flush', action='store_true', help='flush current iptables (firewall) and tc (traffic control) settings.')
    parser.add_argument('--stealth', action='store_true', help='enable stealth mode: suppresses local ICMP/IP leakage and inbound service probes.')
    parser.add_argument('--colorless', action='store_true', help='disable colored output.')

    return parser.parse_args()


def process_arguments(args):
    """
    Processes the specified command-line arguments, adds them to a named tuple
    and returns.
    Executes actions specified in the command line, e.g. flush network settings
    """
    if args.interface is None:
        interface = netutils.get_default_interface()
        if interface is None:
            IO.error('default interface could not be resolved. specify manually (-i).')
            return
    else:
        interface = args.interface
        if not netutils.exists_interface(interface):
            IO.error('interface {}{}{} does not exist.'.format(IO.Fore.LIGHTYELLOW_EX, interface, IO.Style.RESET_ALL))
            return

    IO.ok('interface: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, interface, IO.Style.RESET_ALL))

    if args.gateway_ip is None:
        gateway_ip = netutils.get_default_gateway()
        if gateway_ip is None:
            IO.error('default gateway address could not be resolved. specify manually (-g).')
            return
    else:
        gateway_ip = args.gateway_ip

    IO.ok('gateway ip: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, gateway_ip, IO.Style.RESET_ALL))

    if args.gateway_mac is None:
        gateway_mac = netutils.get_mac_by_ip(interface, gateway_ip)
        if gateway_mac is None:
            IO.error('gateway mac address could not be resolved.')
            return
    else:
        if netutils.validate_mac_address(args.gateway_mac):
            gateway_mac = args.gateway_mac.lower()
        else:
            IO.error('gateway mac is invalid.')
            return

    IO.ok('gateway mac: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, gateway_mac, IO.Style.RESET_ALL))

    if args.netmask is None:
        netmask = netutils.get_default_netmask(interface)
        if netmask is None:
            IO.error('netmask could not be resolved. specify manually (-n).')
            return
    else:
        netmask = args.netmask

    IO.ok('netmask: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, netmask, IO.Style.RESET_ALL))

    if args.stealth:
        IO.ok('stealth mode: {}{}enabled{}'.format(IO.Fore.LIGHTGREEN_EX, IO.Style.BRIGHT, IO.Style.RESET_ALL))

    if args.flush:
        netutils.flush_network_settings(interface)
        IO.spacer()
        IO.ok('flushed network settings')

    return InitialArguments(interface=interface, gateway_ip=gateway_ip, gateway_mac=gateway_mac, netmask=netmask, stealth=args.stealth)


def initialize(interface, gateway_ip=None, gateway_mac=None, stealth=False):
    """
    Initializes network-related settings
    (ip forwarding, qdisc, stealth mode)
    """
    if not netutils.create_qdisc_root(interface):
        IO.spacer()
        IO.error('qdisc root handle could not be created. maybe flush network settings (--flush).')
        return False

    netutils.setup_ifb(interface)

    if not netutils.enable_ip_forwarding(interface, gateway_ip, gateway_mac):
        IO.spacer()
        IO.error('ip forwarding could not be enabled.')
        return False

    if stealth:
        netutils.enable_stealth_mode(interface)

    return True


import signal

_current_menu = None
_current_interface = None


def _emergency_signal_handler(signum, frame):
    global _current_menu, _current_interface
    IO.spacer()
    IO.ok('signal received. performing emergency network cleanup...')
    if _current_menu is not None:
        try:
            _current_menu.interrupt_handler(False)
        except Exception:
            pass
    if _current_interface is not None:
        try:
            cleanup(_current_interface)
        except Exception:
            pass
    sys.exit(0)


def cleanup(interface):
    """
    Resets what has been initialized
    """
    netutils.disable_stealth_mode(interface)
    netutils.delete_ifb(interface)
    netutils.delete_qdisc_root(interface)
    netutils.disable_ip_forwarding()


def run():
    """
    Main entry point of the application
    """
    global _current_menu, _current_interface

    version = get_version()
    args = parse_arguments()

    IO.initialize(args.colorless)
    IO.print(get_main_banner(version))

    if not is_linux():
        IO.error('run under linux.')
        return

    if not is_privileged():
        IO.error('run as root.')
        return

    args = process_arguments(args)

    if args is None:
        return

    _current_interface = args.interface

    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _emergency_signal_handler)

    if initialize(args.interface, args.gateway_ip, args.gateway_mac, args.stealth):
        IO.spacer()        
        menu = MainMenu(version, args.interface, args.gateway_ip, args.gateway_mac, args.netmask)
        _current_menu = menu
        menu.start()
        cleanup(args.interface)


if __name__ == '__main__':
    run()
