import netaddr
import collections
from terminaltables import SingleTable

import evillimiter.networking.utils as netutils
from .menu import CommandMenu
from evillimiter.console.io import IO
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limiter import Limiter
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.scan import HostScanner


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = f'({IO.Style.BRIGHT}Main{IO.Style.RESET_ALL}) >>> '.format()
        self.parser.add_subparser('scan', self._scan_handler)
        self.parser.add_subparser('hosts', self._hosts_handler)
        self.parser.add_subparser('clear', self._clear_handler)

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.version = version          # application version
        self.interface = interface      # specified IPv4 interface
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # range of IP address calculated from gateway IP and netmask
        self.iprange = [str(x) for x in netaddr.IPNetwork(f'{self.gateway_ip}/{self.netmask}')]

        self.host_scanner = HostScanner(self.interface, self.iprange)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        self.limiter = Limiter(self.interface)

        # holds discovered hosts
        self.hosts = []

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()

    def interrupt_handler(self):
        IO.spacer()
        IO.ok('cleaning up... stand by...')

        self.arp_spoofer.stop()
        for host in self.hosts:
            self._free_host(host)

    def _scan_handler(self, args):
        """
        Handles 'scan' command-line argument
        (Re)scans for hosts on the network
        """
        for host in self.hosts:
            self._free_host(host)
            
        IO.spacer()

        self.hosts = self.host_scanner.scan()

        IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{len(self.hosts)}{IO.Style.RESET_ALL} hosts discovered.')
        IO.spacer()

    def _hosts_handler(self, args):
        """
        Handles 'hosts' command-line argument
        Displays discovered hosts
        """
        table_data = [[
            f'{IO.Style.BRIGHT}ID{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}IP-Address{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}MAC-Address{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}Hostname{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}Status{IO.Style.RESET_ALL}'
        ]]
        
        for i, host in enumerate(self.hosts):
            table_data.append([
                f'{IO.Fore.LIGHTYELLOW_EX}{i}{IO.Style.RESET_ALL}',
                host.ip,
                host.mac,
                host.name if host.name is not None else '',
                host.pretty_status()
            ])

        table = SingleTable(table_data, 'Hosts')

        if not table.ok:
            IO.error('table does not fit terminal. resize or decrease font size.')
            return

        IO.spacer()
        IO.print(table.table)
        IO.spacer()

    def _limit_handler(self, args):
        """
        Handles 'limit' command-line argument
        Limits bandwith of host to specified rate
        """
        host = self._get_host_by_id(args.id)
        rate = args.rate

        if host is not None:
            if not host.spoofed:
                self.arp_spoofer.add(host)

            if netutils.validate_netrate_string(rate):
                self.limiter.limit(host, rate)
            else:
                IO.error('limit rate is invalid.')
                return
            
            IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Fore.LIGHTRED_EX} limited{IO.Style.RESET_ALL} to {rate}.')

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        host = self._get_host_by_id(args.id)
        if host is not None:
            if not host.spoofed:
                self.arp_spoofer.add(host)

            self.limiter.block(host)
            IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Fore.RED} blocked{IO.Style.RESET_ALL}.')

    def _free_handler(self, args):
        """
        Handles 'free' command-line argument
        Frees the host from all limitations
        """
        host = self._get_host_by_id(args.id)
        if host is not None:
            self._free_host(host)

    def _clear_handler(self, args):
        """
        Handler for the 'clear' command-line argument
        Clears the terminal window and re-prints the banner
        """
        IO.clear()
        IO.print(get_main_banner(self.version))
        self._print_help_reminder()

    def _help_handler(self, args):
        """
        Handles 'help' command-line argument
        Prints help message including commands and usage
        """
        spaces = ' ' * 20

        IO.print(
            f"""
{IO.Fore.LIGHTYELLOW_EX}scan{IO.Style.RESET_ALL}{spaces[len('scan'):]}scans for online hosts on your network.
{spaces}required to find the hosts you want to limit.

{IO.Fore.LIGHTYELLOW_EX}hosts{IO.Style.RESET_ALL}{spaces[len('hosts'):]}lists all scanned hosts.
{spaces}contains host information, including IDs.

{IO.Fore.LIGHTYELLOW_EX}limit [ID] [rate]{IO.Style.RESET_ALL}{spaces[len('limit [ID] [rate]'):]}limits bandwith of host (uload/dload).
{IO.Style.BRIGHT}{spaces}e.g.: limit 4 100kbit
{spaces}      limit 2 1gbit
{spaces}      limit 5 500tbit{IO.Style.RESET_ALL}

{IO.Fore.LIGHTYELLOW_EX}block [ID]{IO.Style.RESET_ALL}{spaces[len('block [ID]'):]}blocks internet access of host.
{IO.Style.BRIGHT}{spaces}e.g.: block 3{IO.Style.RESET_ALL}

{IO.Fore.LIGHTYELLOW_EX}free [ID]{IO.Style.RESET_ALL}{spaces[len('free [ID]'):]}unlimits/unblocks host.
{IO.Style.BRIGHT}{spaces}e.g.: free 3{IO.Style.RESET_ALL}

{IO.Fore.LIGHTYELLOW_EX}clear{IO.Style.RESET_ALL}{spaces[len('clear'):]}clears the terminal window.
            """
        )

    def _print_help_reminder(self):
        IO.print('type {Y}help{R} or {Y}?{R} to show command information.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_host_by_id(self, id_):
        try:
            identifier = int(id_)
        except ValueError:
            IO.error('identifier is not an integer.')
            return

        if len(self.hosts) == 0 or identifier not in range(len(self.hosts)):
            IO.error(f'no host with id {IO.Fore.LIGHTYELLOW_EX}{identifier}{IO.Style.RESET_ALL}.')
            return

        return self.hosts[identifier]

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host)
            IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Style.RESET_ALL} freed.')