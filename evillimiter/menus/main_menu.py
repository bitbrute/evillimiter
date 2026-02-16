import time
import socket
import curses
import netaddr
import threading
import collections
from terminaltables import SingleTable

import evillimiter.networking.utils as netutils
from .menu import CommandMenu
from evillimiter.networking.utils import BitRate
from evillimiter.console.io import IO
from evillimiter.console.chart import BarChart
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.scan import HostScanner
from evillimiter.networking.monitor import BandwidthMonitor
from evillimiter.networking.watch import HostWatcher


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')
        scan_parser.add_flag('--quick', 'quick')

        rescan_parser = self.parser.add_subparser('rescan', self._rescan_handler)

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')
        limit_parser.add_flag('--full', 'full')
        limit_parser.add_parameterized_flag('--except', 'except_')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')
        block_parser.add_flag('--full', 'full')
        block_parser.add_parameterized_flag('--except', 'except_')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')
        free_parser.add_parameterized_flag('--except', 'except_')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('analyze', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('watch', self._watch_handler)
        watch_add_parser = watch_parser.add_subparser('add', self._watch_add_handler)
        watch_add_parser.add_parameter('id')
        watch_remove_parser = watch_parser.add_subparser('remove', self._watch_remove_handler)
        watch_remove_parser.add_parameter('id')
        watch_set_parser = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set_parser.add_parameter('attribute')
        watch_set_parser.add_parameter('value')

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
        self.host_watcher = HostWatcher(self.host_scanner, self._reconnect_callback)

        # holds discovered hosts
        self.hosts = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()
        # start the bandwidth monitor thread
        self.bandwidth_monitor.start()
        # start the host watch thread
        self.host_watcher.start()

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
        (Re)scans for hosts on the network using deep multi-pass scan
        Use --quick for a fast single-pass scan
        """
        if args.iprange:
            iprange = self._parse_iprange(args.iprange)
            if iprange is None:
                IO.error('invalid ip range.')
                return
        else:
            iprange = None

        with self.hosts_lock:
            for host in self.hosts:
                self._free_host(host)

        if args.quick:
            hosts = self.host_scanner.quick_scan(iprange)
            IO.ok('{} hosts found (quick scan).'.format(len(hosts)))
        else:
            hosts = self.host_scanner.scan(iprange)

        self.hosts_lock.acquire()
        self.hosts = hosts
        self.hosts_lock.release()

        IO.spacer()

    def _rescan_handler(self, args):
        """
        Handles 'rescan' command — rescans and merges new hosts
        without losing status of existing hosts (spoofed/limited/blocked)
        """
        IO.ok('rescanning network (keeping existing host states)...')
        new_hosts = self.host_scanner.scan()

        with self.hosts_lock:
            existing_macs = {h.mac.lower(): h for h in self.hosts}
            added_count = 0

            for new_host in new_hosts:
                mac = new_host.mac.lower()
                if mac in existing_macs:
                    existing = existing_macs[mac]
                    # update IP if changed (device got new DHCP lease)
                    if existing.ip != new_host.ip:
                        old_ip = existing.ip
                        existing.ip = new_host.ip
                        IO.ok('host {} IP changed: {} -> {}'.format(
                            mac, old_ip, new_host.ip))
                    # update hostname/vendor if we got better info
                    if new_host.name and not existing.name:
                        existing.name = new_host.name
                    if new_host.vendor and not existing.vendor:
                        existing.vendor = new_host.vendor
                else:
                    # new host discovered
                    self.hosts.append(new_host)
                    added_count += 1

            IO.ok('{} new hosts added, {} total hosts.'.format(added_count, len(self.hosts)))

        IO.spacer()

    def _hosts_handler(self, args):
        """
        Handles 'hosts' command-line argument
        Displays discovered hosts
        """
        table_data = [[
            '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}MAC address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Vendor{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Hostname{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Status{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        ]]
        
        with self.hosts_lock:
            for host in self.hosts:
                table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host, lock=False), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac,
                    getattr(host, 'vendor', ''),
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
        hosts = self._get_hosts_by_ids(args.id, getattr(args, 'except_', None))
        if hosts is None or len(hosts) == 0:
            return

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate is invalid.')
            return

        direction = self._parse_direction_args(args)

        for host in hosts:
            self.arp_spoofer.add(host)
            self.limiter.limit(host, direction, rate)
            self.bandwidth_monitor.add(host)

            # --full: enable RA kill to force IPv4 fallback
            if args.full:
                host.ipv6_killed = True

            mode_str = ' {}(full mode, IPv6 killed){r}'.format(IO.Fore.CYAN, r=IO.Style.RESET_ALL) if args.full else ''
            IO.ok('{}{}{r} {} {}limited{r} to {}.{}'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.LIGHTRED_EX, rate, mode_str, r=IO.Style.RESET_ALL))

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        hosts = self._get_hosts_by_ids(args.id, getattr(args, 'except_', None))
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)

                # --full: enable RA kill to force IPv4 fallback
                if args.full:
                    host.ipv6_killed = True

                mode_str = ' {}(full mode, IPv6 killed){r}'.format(IO.Fore.CYAN, r=IO.Style.RESET_ALL) if args.full else ''
                IO.ok('{}{}{r} {} {}blocked{r}.{}'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.RED, mode_str, r=IO.Style.RESET_ALL))

    def _free_handler(self, args):
        """
        Handles 'free' command-line argument
        Frees the host from all limitations
        """
        hosts = self._get_hosts_by_ids(args.id, getattr(args, 'except_', None))
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                was_limited = host.limited
                was_blocked = host.blocked
                was_spoofed = host.spoofed
                was_ipv6_killed = host.ipv6_killed

                self._free_host(host)

                # build detailed confirmation message
                actions = []
                if was_spoofed:
                    actions.append('ARP restored')
                if was_ipv6_killed:
                    actions.append('IPv6 restored')
                if was_limited:
                    actions.append('limit removed')
                if was_blocked:
                    actions.append('block removed')

                detail = ' ({})'.format(', '.join(actions)) if actions else ''
                IO.ok('{}{}{r} {}freed{r}.{}'.format(
                    IO.Fore.LIGHTYELLOW_EX, host.ip,
                    IO.Fore.LIGHTGREEN_EX,
                    detail,
                    r=IO.Style.RESET_ALL
                ))

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

        with self.hosts_lock:
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
            with self.hosts_lock:
                return [x for x in [(y, self.bandwidth_monitor.get(y)) for y in self.hosts] if x[1] is not None]

        def display(stdscr, interval):
            host_results = get_bandwidth_results()
            hname_max_len = max([len(x[0].name) for x in host_results])

            header_off = [
                ('ID', 5), ('IP address', 18), ('Hostname', hname_max_len + 2),
                ('Status', 18), ('IPv6', 10),
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

                for host, result in host_results:
                    # determine status string
                    if host.blocked:
                        status_str = 'Blocked'
                    elif host.limited:
                        limit_info = self.limiter._host_dict.get(host)
                        if limit_info and 'rate' in limit_info:
                            status_str = 'Limited {}'.format(limit_info['rate'])
                        else:
                            status_str = 'Limited'
                    else:
                        status_str = 'Spoofed'

                    # IPv6 status: RA kill is active when host is spoofed
                    ipv6_str = 'Killed' if host.ipv6_killed else '-'

                    result_data = [
                        str(self._get_host_id(host)),
                        host.ip,
                        host.name,
                        status_str,
                        ipv6_str,
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

    def _analyze_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            IO.error('no hosts to be analyzed.')
            return
        
        duration = 30 # in s
        if args.duration:
            if not args.duration.isdigit():
                IO.error('invalid duration.')
                return

            duration = int(args.duration)

        hosts_to_be_freed = set()
        host_values = {}

        for host in hosts:
            if not host.spoofed:
                hosts_to_be_freed.add(host)

            self.arp_spoofer.add(host)
            self.bandwidth_monitor.add(host)

            host_result = self.bandwidth_monitor.get(host)
            host_values[host] = {}
            host_values[host]['prev'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('analyzing traffic for {}s.'.format(duration))
        time.sleep(duration)

        error_occurred = False
        for host in hosts:
            host_result = self.bandwidth_monitor.get(host)

            if host_result is None:
                # host reconnected during analysis
                IO.error('host reconnected during analysis.')
                error_occurred = True
            else:
                host_values[host]['current'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('cleaning up...')
        for host in hosts_to_be_freed:
            self._free_host(host)

        if error_occurred:
            return

        upload_chart = BarChart(max_bar_length=29)
        download_chart = BarChart(max_bar_length=29)

        for host in hosts:
            upload_value = host_values[host]['current'][0] - host_values[host]['prev'][0]
            download_value = host_values[host]['current'][1] - host_values[host]['prev'][1]

            prefix = '{}{}{} ({}, {})'.format(
                IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL,
                host.ip,
                host.name
            )
            
            upload_chart.add_value(upload_value.value, prefix, upload_value)
            download_chart.add_value(download_value.value, prefix, download_value)

        upload_table = SingleTable([[upload_chart.get()]], 'Upload')
        download_table = SingleTable([[download_chart.get()]], 'Download')

        upload_table.inner_heading_row_border = False
        download_table.inner_heading_row_border = False

        IO.spacer()
        IO.print(upload_table.table)
        IO.print(download_table.table)
        IO.spacer()

    def _watch_handler(self, args):
        if len(args) == 0:
            watch_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}MAC address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            set_table_data = [[
                '{}Attribute{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Value{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            hist_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Old IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}New IP address{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Time{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            iprange = self.host_watcher.iprange
            interval = self.host_watcher.interval

            set_table_data.append([
                '{}range{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{} addresses'.format(len(iprange)) if iprange is not None else 'default'
            ])

            set_table_data.append([
                '{}interval{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{}s'.format(interval)
            ])

            for host in self.host_watcher.hosts:
                watch_table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac
                ])

            for recon in self.host_watcher.log_list:
                hist_table_data.append([
                    recon['old'].mac,
                    recon['old'].ip,
                    recon['new'].ip,
                    recon['time']
                ])

            watch_table = SingleTable(watch_table_data, "Watchlist")
            set_table = SingleTable(set_table_data, "Settings")
            hist_table = SingleTable(hist_table_data, 'Reconnection History')

            IO.spacer()
            IO.print(watch_table.table)
            IO.spacer()
            IO.print(set_table.table)
            IO.spacer()
            IO.print(hist_table.table)
            IO.spacer()

    def _watch_add_handler(self, args):
        """
        Handles 'watch add' command-line argument
        Adds host to the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.add(host)

    def _watch_remove_handler(self, args):
        """
        Handles 'watch remove' command-line argument
        Removes host from the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.remove(host)

    def _watch_set_handler(self, args):
        """
        Handles 'watch set' command-line argument
        Modifies settings of the reconnection reconnection watcher
        """
        if args.attribute.lower() in ('range', 'iprange', 'ip_range'):
            iprange = self._parse_iprange(args.value)
            if iprange is not None:
                self.host_watcher.iprange = iprange
            else:
                IO.error('invalid ip range.')
        elif args.attribute.lower() in ('interval'):
            if args.value.isdigit():
                self.host_watcher.interval = int(args.value)
            else:
                IO.error('invalid interval.')
        else:
            IO.error('{}{}{} is an invalid settings attribute.'.format(IO.Fore.LIGHTYELLOW_EX, args.attribute, IO.Style.RESET_ALL))

    def _reconnect_callback(self, old_host, new_host):
        """
        Callback that is called when a watched host reconnects
        Method will run in a separate thread
        """
        with self.hosts_lock:
            if old_host in self.hosts:
                self.hosts[self.hosts.index(old_host)] = new_host
            else:
                return

        self.arp_spoofer.remove(old_host, restore=False)
        self.arp_spoofer.add(new_host)

        self.host_watcher.remove(old_host)
        self.host_watcher.add(new_host)

        self.limiter.replace(old_host, new_host)
        self.bandwidth_monitor.replace(old_host, new_host)

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
{y}scan (--range [IP range]) (--quick){r}{}scans for online hosts using ultra-deep multi-method scan.
{s}8 methods: ARP broadcast, passive ARP sniffing,
{s}ICMP ping sweep, mDNS, NetBIOS, TCP SYN probe,
{s}unicast ARP, DHCP leases.
{s}use --quick for fast single-pass ARP scan.
{b}{s}e.g.: scan
{s}      scan --quick
{s}      scan --range 192.168.178.1-192.168.178.50
{s}      scan --range 192.168.178.1/24{r}

{y}rescan{r}{}rescans & merges new hosts without losing
{s}existing host states (spoofed/limited/blocked).

{y}hosts (--force){r}{}lists all scanned hosts.
{s}contains host information, including IDs.

{y}limit [ID1,ID2,...] [rate]{r}{}limits bandwith of host(s) (uload/dload).
{y}      (--upload) (--download){r}{}{b}e.g.: limit 4 100kbit
{s}      limit 2,3,4 1gbit --download
{s}      limit all 200kbit --upload
{s}      limit 2 200kbit --full  (kills IPv6)
{s}      limit all 200kbit --except 0,10{r}

{y}block [ID1,ID2,...]{r}{}blocks internet access of host(s).
{y}      (--upload) (--download){r}{}{b}e.g.: block 3,2
{s}      block all --upload
{s}      block 2 --full  (kills IPv6)
{s}      block all --except 0,10{r}

{y}free [ID1,ID2,...]{r}{}unlimits/unblocks host(s).
{b}{s}e.g.: free 3
{s}      free all
{s}      free all --except 5{r}

{y}add [IP] (--mac [MAC]){r}{}adds custom host to host list.
{s}mac resolved automatically.
{b}{s}e.g.: add 192.168.178.24
{s}      add 192.168.1.50 --mac 1c:fc:bc:2d:a6:37{r}

{y}monitor (--interval [time in ms]){r}{}monitors bandwidth usage of limited host(s).
{b}{s}e.g.: monitor --interval 600{r}

{y}analyze [ID1,ID2,...]{r}{}analyzes traffic of host(s) without limiting
{y}        (--duration [time in s]){r}{}to determine who uses how much bandwidth.
{b}{s}e.g.: analyze 2,3 --duration 120{r}

{y}watch{r}{}detects host reconnects with different IP.
{y}watch add [ID1,ID2,...]{r}{}adds host to the reconnection watchlist.
{b}{s}e.g.: watch add 3,4{r}
{y}watch remove [ID1,ID2,...]{r}{}removes host from the reconnection watchlist.
{b}{s}e.g.: watch remove all{r}
{y}watch set [attr] [value]{r}{}changes reconnect watch settings.
{b}{s}e.g.: watch set interval 120{r}

{y}clear{r}{}clears the terminal window.

{y}quit{r}{}quits the application.
            """.format(
                    spaces[len('scan (--range [IP range]) (--quick)'):],
                    spaces[len('rescan'):],
                    spaces[len('hosts (--force)'):],
                    spaces[len('limit [ID1,ID2,...] [rate]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('block [ID1,ID2,...]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('free [ID1,ID2,...]'):],
                    spaces[len('add [IP] (--mac [MAC])'):],
                    spaces[len('monitor (--interval [time in ms])'):],
                    spaces[len('analyze [ID1,ID2,...]'):],
                    spaces[len('        (--duration [time in s])'):],
                    spaces[len('watch'):],
                    spaces[len('watch add [ID1,ID2,...]'):],
                    spaces[len('watch remove [ID1,ID2,...]'):],
                    spaces[len('watch set [attr] [value]'):],
                    spaces[len('clear'):],
                    spaces[len('quit'):],
                    y=IO.Fore.LIGHTYELLOW_EX, r=IO.Style.RESET_ALL, b=IO.Style.BRIGHT,
                    s=spaces
                )
        )

    def _quit_handler(self, args):
        self.interrupt_handler(False)
        self.stop()

    def _get_host_id(self, host, lock=True):
        ret = None

        if lock:
            self.hosts_lock.acquire()

        for i, host_ in enumerate(self.hosts):
            if host_ == host:
                ret = i
                break
        
        if lock:
            self.hosts_lock.release()

        return ret

    def _print_help_reminder(self):
        IO.print('type {Y}help{R} or {Y}?{R} to show command information.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_hosts_by_ids(self, ids_string, except_string=None):
        if ids_string == 'all':
            with self.hosts_lock:
                hosts = set(self.hosts.copy())
        else:
            ids = ids_string.split(',')
            hosts = set()

            with self.hosts_lock:
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

        # --except: remove excluded hosts from the result
        if except_string:
            except_ids = except_string.split(',')
            except_hosts = set()
            with self.hosts_lock:
                for eid in except_ids:
                    if eid.isdigit():
                        idx = int(eid)
                        if idx in range(len(self.hosts)):
                            except_hosts.add(self.hosts[idx])
                    else:
                        for host in self.hosts:
                            if host.mac == eid.lower() or host.ip == eid:
                                except_hosts.add(host)
                                break
            hosts -= except_hosts
            if except_hosts:
                excluded = ', '.join(h.ip for h in except_hosts)
                IO.ok('excluding: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, excluded, IO.Style.RESET_ALL))

        return hosts

    def _parse_direction_args(self, args):
        direction = Direction.NONE

        if args.upload:
            direction |= Direction.OUTGOING
        if args.download:
            direction |= Direction.INCOMING

        return Direction.BOTH if direction == Direction.NONE else direction

    def _parse_iprange(self, range):
        try:
            if '-' in range:
                return list(netaddr.iter_iprange(*range.split('-')))
            else:
                return list(netaddr.IPNetwork(range))
        except netaddr.core.AddrFormatError:
            return

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)
