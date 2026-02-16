import threading

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES


class Limiter(object):
    class HostLimitIDs(object):
        def __init__(self, upload_id, download_id):
            self.upload_id = upload_id
            self.download_id = download_id

    def __init__(self, interface):
        self.interface = interface
        self._host_dict = {}
        self._host_dict_lock = threading.Lock()

    def limit(self, host, direction, rate):
        """
        Limits the uload/dload traffic of a host
        to a specified rate with high accuracy.
        Uses HTB + SFQ for precise rate control,
        MAC-based iptables rules for reliability (survives IP changes),
        and conntrack marks for established connections.
        """
        host_ids = self._new_host_limit_ids(host, direction)

        # Calculate proper burst size:
        # HTB burst should be at least rate/HZ (typically HZ=250 on Linux)
        # We use rate/8 (bits to bytes) / 250 * 1.5 for safety
        # Minimum burst of 15k to handle small rates properly
        burst_value = max(15000, int(rate.rate / 8 / 250 * 1.5))
        burst_str = '{}b'.format(burst_value)

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # add a class to the root qdisc with specified rate
            shell.execute_suppressed('{} class add dev {} parent 1:0 classid 1:{} htb rate {} burst {} cburst {}'.format(
                BIN_TC, self.interface, host_ids.upload_id, rate, burst_str, burst_str))
            # add SFQ leaf qdisc for fair queuing within the class (more accurate shaping)
            shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}0: sfq perturb 10'.format(
                BIN_TC, self.interface, host_ids.upload_id, host_ids.upload_id))
            # add a fw filter that filters packets marked with the corresponding ID
            shell.execute_suppressed('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(
                BIN_TC, self.interface, id=host_ids.upload_id))
            # marks outgoing packets by IP
            shell.execute_suppressed('{} -t mangle -A POSTROUTING -s {} -j MARK --set-mark {}'.format(
                BIN_IPTABLES, host.ip, host_ids.upload_id))
            # also mark by MAC (survives IP changes from DHCP)
            shell.execute_suppressed('{} -t mangle -A POSTROUTING -m mac --mac-source {} -j MARK --set-mark {}'.format(
                BIN_IPTABLES, host.mac, host_ids.upload_id))
            # save mark to connection (connmark) so established connections are also limited
            shell.execute_suppressed('{} -t mangle -A POSTROUTING -s {} -j CONNMARK --save-mark'.format(
                BIN_IPTABLES, host.ip))

        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # add a class to the root qdisc with specified rate
            shell.execute_suppressed('{} class add dev {} parent 1:0 classid 1:{} htb rate {} burst {} cburst {}'.format(
                BIN_TC, self.interface, host_ids.download_id, rate, burst_str, burst_str))
            # add SFQ leaf qdisc for fair queuing
            shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}0: sfq perturb 10'.format(
                BIN_TC, self.interface, host_ids.download_id, host_ids.download_id))
            # add a fw filter that filters packets marked with the corresponding ID
            shell.execute_suppressed('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(
                BIN_TC, self.interface, id=host_ids.download_id))
            # marks incoming packets
            shell.execute_suppressed('{} -t mangle -A PREROUTING -d {} -j MARK --set-mark {}'.format(
                BIN_IPTABLES, host.ip, host_ids.download_id))
            # restore connmark for existing connections heading to this host
            shell.execute_suppressed('{} -t mangle -A PREROUTING -d {} -j CONNMARK --restore-mark'.format(
                BIN_IPTABLES, host.ip))

        host.limited = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': rate, 'direction': direction }

    def block(self, host, direction):
        host_ids = self._new_host_limit_ids(host, direction)

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # drops forwarded packets with matching source IP
            shell.execute_suppressed('{} -A FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
            # also drop by MAC (survives DHCP IP changes)
            shell.execute_suppressed('{} -A FORWARD -m mac --mac-source {} -j DROP'.format(BIN_IPTABLES, host.mac))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # drops forwarded packets with matching destination
            shell.execute_suppressed('{} -A FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip))
            # drop related/established connections too (prevents lingering)
            shell.execute_suppressed('{} -A FORWARD -d {} -m conntrack --ctstate ESTABLISHED,RELATED -j DROP'.format(BIN_IPTABLES, host.ip))

        host.blocked = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': None, 'direction': direction }

    def unlimit(self, host, direction):
        if not host.limited and not host.blocked:
            return
            
        with self._host_dict_lock:
            host_ids = self._host_dict[host]['ids']

            if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                self._delete_tc_class(host_ids.upload_id)
                self._delete_iptables_entries(host, direction, host_ids.upload_id)
            if (direction & Direction.INCOMING) == Direction.INCOMING:
                self._delete_tc_class(host_ids.download_id)
                self._delete_iptables_entries(host, direction, host_ids.download_id)

            del self._host_dict[host]

        host.limited = False
        host.blocked = False

    def replace(self, old_host, new_host):
        self._host_dict_lock.acquire()
        info = self._host_dict[old_host] if old_host in self._host_dict else None
        self._host_dict_lock.release()

        if info is not None:
            self.unlimit(old_host, Direction.BOTH)

            if info['rate'] is None:
                self.block(new_host, info['direction'])
            else:
                self.limit(new_host, info['direction'], info['rate'])

    def _new_host_limit_ids(self, host, direction):
        """
        Get limit information for corresponding host
        If not present, create new 
        """
        host_ids = None

        self._host_dict_lock.acquire()
        present = host in self._host_dict
        self._host_dict_lock.release()

        if present:
                host_ids = self._host_dict[host]['ids']
                self.unlimit(host, direction)
        
        return Limiter.HostLimitIDs(*self._create_ids()) if host_ids is None else host_ids

    def _create_ids(self):
        """
        Returns unique IDs that are
        currently not in use
        """
        def generate_id(*exc):
            """
            Generates a unique, unused ID
            exc: IDs that will not be used (exceptions)
            """
            id_ = 1
            with self._host_dict_lock:
                while True:
                    if id_ not in exc:
                        v = (x for x in self._host_dict.values())
                        ids = (x['ids'] for x in v)
                        if id_ not in (x for y in ids for x in [y.upload_id, y.download_id]):
                            return id_
                    id_ += 1

        id1 = generate_id()
        return (id1, generate_id(id1))

    def _delete_tc_class(self, id_):
        """
        Deletes the tc class, SFQ leaf qdisc, and applied filters
        for a given ID (host)
        """
        shell.execute_suppressed('{} filter del dev {} parent 1:0 prio {}'.format(BIN_TC, self.interface, id_))
        # remove SFQ leaf qdisc first
        shell.execute_suppressed('{} qdisc del dev {} parent 1:{} handle {}0:'.format(BIN_TC, self.interface, id_, id_))
        shell.execute_suppressed('{} class del dev {} parent 1:0 classid 1:{}'.format(BIN_TC, self.interface, id_))

    def _delete_iptables_entries(self, host, direction, id_):
        """
        Deletes iptables rules for a given ID (host)
        Removes all rules: IP-based, MAC-based, connmark, and conntrack
        """
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            shell.execute_suppressed('{} -t mangle -D POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
            shell.execute_suppressed('{} -t mangle -D POSTROUTING -m mac --mac-source {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.mac, id_))
            shell.execute_suppressed('{} -t mangle -D POSTROUTING -s {} -j CONNMARK --save-mark'.format(BIN_IPTABLES, host.ip))
            shell.execute_suppressed('{} -D FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
            shell.execute_suppressed('{} -D FORWARD -m mac --mac-source {} -j DROP'.format(BIN_IPTABLES, host.mac))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            shell.execute_suppressed('{} -t mangle -D PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
            shell.execute_suppressed('{} -t mangle -D PREROUTING -d {} -j CONNMARK --restore-mark'.format(BIN_IPTABLES, host.ip))
            shell.execute_suppressed('{} -D FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip))
            shell.execute_suppressed('{} -D FORWARD -d {} -m conntrack --ctstate ESTABLISHED,RELATED -j DROP'.format(BIN_IPTABLES, host.ip))


class Direction:
    NONE = 0
    OUTGOING = 1
    INCOMING = 2
    BOTH = 3

    def pretty_direction(direction):
        if direction == Direction.OUTGOING:
            return 'upload'
        elif direction == Direction.INCOMING:
            return 'download'
        elif direction == Direction.BOTH:
            return 'upload / download'
        else:
            return '-'
