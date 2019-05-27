import socket
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
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('hosts', self._hosts_handler)
        self.parser.add_subparser('clear', self._clear_handler)

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.version = version          # application version
        self.interface = interface      # specified IPv4 interface
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # range of IP address calculated from gateway IP and netmask
        self.iprange = list(netaddr.IPNetwork('{}/{}'.format(self.gateway_ip, self.netmask)))

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
        if args.iprange:
            try:
                if '-' in args.iprange:
                    iprange = list(netaddr.iter_iprange(*args.iprange.split('-')))
                else:
                    iprange = list(netaddr.IPNetwork(args.iprange))
            except netaddr.core.AddrFormatError:
                IO.error('ip range invalid.')
                return
        else:
            iprange = None

        for host in self.hosts:
            self._free_host(host)
            
        IO.spacer()

        self.hosts = self.host_scanner.scan(iprange)

        IO.ok('{}{}{} hosts discovered.'.format(IO.Fore.LIGHTYELLOW_EX, len(self.hosts), IO.Style.RESET_ALL))
        IO.spacer()

    def _hosts_handler(self, args):
        """
        Handles 'hosts' command-line argument
        Displays discovered hosts
        """
        table_data = [[
            '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}IP-Address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}MAC-Address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Hostname{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Status{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        ]]
        
        for i, host in enumerate(self.hosts):
            table_data.append([
                '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, i, IO.Style.RESET_ALL),
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
        hosts = self._get_hosts_by_ids(args.id)
        rate = args.rate

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                if netutils.validate_netrate_string(rate):
                    self.limiter.limit(host, rate)
                else:
                    IO.error('limit rate is invalid.')
                    return
                
                IO.ok('{}{}{} limited{} to {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL, rate))

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host)
                IO.ok('{}{}{} blocked{}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Fore.RED, IO.Style.RESET_ALL))

    def _free_handler(self, args):
        """
        Handles 'free' command-line argument
        Frees the host from all limitations
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self._free_host(host)

    def _add_handler(self, args):
        """
        Handles 'add' command-line argument
        Adds custom host to host list
        """
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('invalid ip address.')
            return

        if args.mac:
            mac = args.mac
            if not netutils.validate_mac_address(mac):
                IO.error('invalid mac address.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if mac is None:
                IO.error('unable to resolve mac address. specify manually (--mac).')
                return

        name = None
        try:
            host_info = socket.gethostbyaddr(ip)
            name = None if host_info is None else host_info[0]
        except socket.herror:
            pass

        host = Host(ip, mac, name)
        if host in self.hosts:
            IO.error('host does already exist.')
            return

        self.hosts.append(host)   
        IO.ok('host added.') 

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
        spaces = ' ' * 30

        IO.print(
            """
{y}scan (--range [IP range]){r}{}scans for online hosts on your network.
{s}required to find the hosts you want to limit.
{b}{s}e.g.: scan
{s}      scan --range 192.168.178.1-192.168.178.50
{s}      scan --range 192.168.178.1/24{r}

{y}hosts{r}{}lists all scanned hosts.
{s}contains host information, including IDs.

{y}limit [ID1,ID2,...] [rate]{r}{}limits bandwith of host(s) (uload/dload).
{b}{s}e.g.: limit 4 100kbit
{s}      limit 2,3,4 1gbit
{s}      limit all 200kbit{r}

{y}block [ID1,ID2,...]{r}{}blocks internet access of host(s).
{b}{s}e.g.: block 3,2
{s}      block all{r}

{y}free [ID1,ID2,...]{r}{}unlimits/unblocks host(s).
{b}{s}e.g.: free 3
{s}      free all{r}

{y}add [IP] (--mac [MAC]){r}{}adds custom host to host list.
{s}mac resolved automatically.
{b}{s}e.g.: add 192.168.178.24
{s}      add 192.168.1.50 --mac 1c:fc:bc:2d:a6:37{r}

{y}clear{r}{}clears the terminal window.
            """.format(
                    spaces[len('scan (--range [IP range])'):],
                    spaces[len('hosts'):],
                    spaces[len('limit [ID1,ID2,...] [rate]'):],
                    spaces[len('block [ID1,ID2,...]'):],
                    spaces[len('free [ID1,ID2,...]'):],
                    spaces[len('add [IP] (--mac [MAC])'):],
                    spaces[len('clear'):],
                    y=IO.Fore.LIGHTYELLOW_EX, r=IO.Style.RESET_ALL, b=IO.Style.BRIGHT,
                    s=spaces
                )
        )

    def _print_help_reminder(self):
        IO.print('type {Y}help{R} or {Y}?{R} to show command information.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_hosts_by_ids(self, ids_string):
        if ids_string == 'all':
            return self.hosts.copy()

        try:
            ids = [int(x) for x in ids_string.split(',')]
        except ValueError:
            IO.error('\'{}\' are invalid IDs.'.format(ids_string))
            return

        hosts = []

        for id_ in ids:
            if len(self.hosts) == 0 or id_ not in range(len(self.hosts)):
                IO.error('no host with id {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                return
            if self.hosts[id_] not in hosts:
                hosts.append(self.hosts[id_])

        return hosts

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host)
            IO.ok('{}{}{} freed.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Style.RESET_ALL))