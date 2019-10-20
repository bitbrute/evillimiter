import time
import socket
import curses
import netaddr
import collections
from terminaltables import SingleTable

import evillimiter.networking.utils as netutils
from .menu import CommandMenu
from evillimiter.networking.utils import BitRate
from evillimiter.console.io import IO
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.scan import HostScanner
from evillimiter.networking.monitor import BandwidthMonitor


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.parser.add_subparser('quit', self._quit_handler)
        self.parser.add_subparser('exit', self._quit_handler)

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
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1)

        # holds discovered hosts
        self.hosts = []

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()
        # start the bandwidth monitor thread
        self.bandwidth_monitor.start()

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()

        IO.ok('cleaning up... stand by...')

        self.arp_spoofer.stop()
        self.bandwidth_monitor.stop()

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
                host.name,
                host.pretty_status()
            ])

        table = SingleTable(table_data, 'Hosts')

        if not args.force and not table.ok:
            IO.error('table does not fit terminal. resize or decrease font size. you can also force the display (--force).')
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

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate is invalid.')
            return

        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.limit(host, direction, rate)
                self.bandwidth_monitor.add(host)
                IO.ok('{}{}{r} {} {}limited{r} to {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.LIGHTRED_EX, rate, r=IO.Style.RESET_ALL))

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        hosts = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)
                IO.ok('{}{}{r} {} {}blocked{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.RED, r=IO.Style.RESET_ALL))

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

    def _monitor_handler(self, args):
        """
        Handles 'monitor' command-line argument
        Monitors hosts bandwidth usage
        """
        def get_bandwidth_results():
            return [x for x in [(y, self.bandwidth_monitor.get(y)) for y in self.hosts] if x[1] is not None]

        def display(stdscr, interval):
            host_results = get_bandwidth_results()
            hname_max_len = max([len(x[0].name) for x in host_results])

            header_off = [
                ('ID', 5), ('IP-Address', 18), ('Hostname', hname_max_len + 2),
                ('Current (per s)', 20), ('Total', 16), ('Packets', 0)
            ]

            y_rst = 1
            x_rst = 2

            while True:
                y_off = y_rst
                x_off = x_rst

                stdscr.clear()

                for header in header_off:
                    stdscr.addstr(y_off, x_off, header[0])
                    x_off += header[1]

                y_off += 2
                x_off = x_rst

                for i, (host, result) in enumerate(host_results):
                    result_data = [
                        str(i),
                        host.ip,
                        host.name,
                        '{}↑ {}↓'.format(result.upload_rate, result.download_rate),
                        '{}↑ {}↓'.format(result.upload_total_size, result.download_total_size),
                        '{}↑ {}↓'.format(result.upload_total_count, result.download_total_count)
                    ]

                    for j, string in enumerate(result_data):
                        stdscr.addstr(y_off, x_off, string)
                        x_off += header_off[j][1]

                    y_off += 1
                    x_off = x_rst

                y_off += 2
                stdscr.addstr(y_off, x_off, 'press \'ctrl+c\' to exit.')

                try:
                    stdscr.refresh()
                    time.sleep(interval)
                    host_results = get_bandwidth_results()
                except KeyboardInterrupt:
                    return
                    

        interval = 0.5  # in s
        if args.interval:
            if not args.interval.isdigit():
                IO.error('invalid interval.')
                return

            interval = int(args.interval) / 1000    # from ms to s

        if len(get_bandwidth_results()) == 0:
            IO.error('no hosts to be monitored.')
            return

        try:
            curses.wrapper(display, interval)
        except curses.error:
            IO.error('monitor error occurred. maybe terminal too small?')

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
        spaces = ' ' * 35

        IO.print(
            """
{y}scan (--range [IP range]){r}{}scans for online hosts on your network.
{s}required to find the hosts you want to limit.
{b}{s}e.g.: scan
{s}      scan --range 192.168.178.1-192.168.178.50
{s}      scan --range 192.168.178.1/24{r}

{y}hosts (--force){r}{}lists all scanned hosts.
{s}contains host information, including IDs.

{y}limit [ID1,ID2,...] [rate]{r}{}limits bandwith of host(s) (uload/dload).
{y}      (--upload) (--download){r}{}{b}e.g.: limit 4 100kbit
{s}      limit 2,3,4 1gbit --download
{s}      limit all 200kbit --upload{r}

{y}block [ID1,ID2,...]{r}{}blocks internet access of host(s).
{y}      (--upload) (--download){r}{}{b}e.g.: block 3,2
{s}      block all --upload{r}

{y}free [ID1,ID2,...]{r}{}unlimits/unblocks host(s).
{b}{s}e.g.: free 3
{s}      free all{r}

{y}add [IP] (--mac [MAC]){r}{}adds custom host to host list.
{s}mac resolved automatically.
{b}{s}e.g.: add 192.168.178.24
{s}      add 192.168.1.50 --mac 1c:fc:bc:2d:a6:37{r}

{y}monitor (--interval [time in ms]){r}{}monitors bandwidth usage of limited hosts.
{b}{s}e.g.: monitor --interval 600{r}

{y}clear{r}{}clears the terminal window.

{y}quit{r}{}quits the application.
            """.format(
                    spaces[len('scan (--range [IP range])'):],
                    spaces[len('hosts (--force)'):],
                    spaces[len('limit [ID1,ID2,...] [rate]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('block [ID1,ID2,...]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('free [ID1,ID2,...]'):],
                    spaces[len('add [IP] (--mac [MAC])'):],
                    spaces[len('monitor (--interval [time in ms])'):],
                    spaces[len('clear'):],
                    spaces[len('quit'):],
                    y=IO.Fore.LIGHTYELLOW_EX, r=IO.Style.RESET_ALL, b=IO.Style.BRIGHT,
                    s=spaces
                )
        )

    def _quit_handler(self, args):
        self.interrupt_handler(False)
        self.stop()

    def _print_help_reminder(self):
        IO.print('type {Y}help{R} or {Y}?{R} to show command information.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_hosts_by_ids(self, ids_string):
        if ids_string == 'all':
            return self.hosts.copy()

        ids = ids_string.split(',')
        hosts = set()

        for id_ in ids:
            is_mac = netutils.validate_mac_address(id_)
            is_ip = netutils.validate_ip_address(id_)
            is_id_ = id_.isdigit()

            if not is_mac and not is_ip and not is_id_:
                IO.error('invalid identifier(s): \'{}\'.'.format(ids_string))
                return

            if is_mac or is_ip:
                found = False
                for host in self.hosts:
                    if host.mac == id_.lower() or host.ip == id_:
                        found = True
                        hosts.add(host)
                        break
                if not found:
                    IO.error('no host matching {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                    return
            else:
                id_ = int(id_)
                if len(self.hosts) == 0 or id_ not in range(len(self.hosts)):
                    IO.error('no host with id {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                    return
                hosts.add(self.hosts[id_])

        return hosts

    def _parse_direction_args(self, args):
        direction = Direction.NONE

        if args.upload:
            direction |= Direction.OUTGOING
        if args.download:
            direction |= Direction.INCOMING

        return Direction.BOTH if direction == Direction.NONE else direction

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            IO.ok('{}{}{} freed.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, IO.Style.RESET_ALL))