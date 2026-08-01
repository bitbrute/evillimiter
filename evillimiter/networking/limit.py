import threading

import evillimiter.console.shell as shell
import evillimiter.networking.utils as netutils
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
        Limits the upload/download traffic of a host to a specified rate
        with dynamic burst/quantum calculation and FQ_CoDel/SFQ fair queueing.
        """
        host_ids = self._new_host_limit_ids(host, direction)

        # Calculate dynamic token bucket burst & quantum scaled to requested bitrate
        # Enforce minimum burst floor of 15000 bytes (~10 MTU frames) to prevent packet starvation at low rates
        bytes_per_sec = rate.rate / 8.0 if hasattr(rate, 'rate') else 100000.0
        burst_bytes = max(15000, min(128000, int(bytes_per_sec * 0.10)))
        quantum_bytes = max(1500, min(60000, int(bytes_per_sec / 5.0)))

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # 1. Add class with dynamic burst (bytes) and quantum (bytes)
            shell.execute_suppressed(
                '{} class add dev {} parent 1:0 classid 1:{} htb rate {r} ceil {r} burst {} quantum {}'.format(
                    BIN_TC, self.interface, host_ids.upload_id, burst_bytes, quantum_bytes, r=rate
                )
            )
            # 2. Attach FQ_CoDel leaf qdisc (fallback to SFQ if fq_codel unsupported by kernel)
            if shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}: fq_codel limit 1024 flows 1024 target 5ms interval 100ms'.format(
                BIN_TC, self.interface, host_ids.upload_id, host_ids.upload_id
            )) != 0:
                shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}: sfq perturb 10'.format(
                    BIN_TC, self.interface, host_ids.upload_id, host_ids.upload_id
                ))
            # 3. Add tc filter matching protocol all
            shell.execute_suppressed(
                '{} filter add dev {} parent 1:0 protocol all prio {id} handle {id} fw flowid 1:{id}'.format(
                    BIN_TC, self.interface, id=host_ids.upload_id
                )
            )
            # 4. Mark outgoing packets
            if host.mac:
                shell.execute_suppressed('{} -t mangle -I POSTROUTING 1 -s {} -m mac --mac-source {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host.mac, host_ids.upload_id))
            else:
                shell.execute_suppressed('{} -t mangle -I POSTROUTING 1 -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host_ids.upload_id))

        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # 1. Add class with dynamic burst (bytes) and quantum (bytes) on IFB device (ifb0) for ingress shaping
            ifb_dev = 'ifb0'
            shell.execute_suppressed(
                '{} class add dev {} parent 1:0 classid 1:{} htb rate {r} ceil {r} burst {} quantum {}'.format(
                    BIN_TC, ifb_dev, host_ids.download_id, burst_bytes, quantum_bytes, r=rate
                )
            )
            # 2. Attach FQ_CoDel leaf qdisc (fallback to SFQ)
            if shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}: fq_codel limit 1024 flows 1024 target 5ms interval 100ms'.format(
                BIN_TC, ifb_dev, host_ids.download_id, host_ids.download_id
            )) != 0:
                shell.execute_suppressed('{} qdisc add dev {} parent 1:{} handle {}: sfq perturb 10'.format(
                    BIN_TC, ifb_dev, host_ids.download_id, host_ids.download_id
                ))
            # 3. Add tc filter matching protocol ip destination on IFB device (u32 match ip dst)
            shell.execute_suppressed(
                '{} filter add dev {} parent 1:0 protocol ip prio {id} u32 match ip dst {}/32 flowid 1:{id}'.format(
                    BIN_TC, ifb_dev, host.ip, id=host_ids.download_id
                )
            )
            # 4. Add selective ingress redirect on physical interface for host.ip only
            netutils.add_ifb_redirect(self.interface, host.ip, host_ids.download_id, ifb_dev)

            # 5. Mark incoming packets
            shell.execute_suppressed('{} -t mangle -I PREROUTING 1 -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host_ids.download_id))

        host.limited = True

        netutils.flush_conntrack(host.ip)

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': rate, 'direction': direction }

    def block(self, host, direction):
        host_ids = self._new_host_limit_ids(host, direction)

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # drops forwarded packets with matching source (inserted at head of chain)
            if host.mac:
                shell.execute_suppressed('{} -t filter -I FORWARD 1 -s {} -m mac --mac-source {} -j DROP'.format(BIN_IPTABLES, host.ip, host.mac))
            else:
                shell.execute_suppressed('{} -t filter -I FORWARD 1 -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # drops forwarded packets with matching destination
            shell.execute_suppressed('{} -t filter -I FORWARD 1 -d {} -j DROP'.format(BIN_IPTABLES, host.ip))

        host.blocked = True

        netutils.flush_conntrack(host.ip)

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
                netutils.del_ifb_redirect(self.interface, host_ids.download_id)
                self._delete_tc_class(host_ids.download_id)
                self._delete_iptables_entries(host, direction, host_ids.download_id)

            del self._host_dict[host]

        host.limited = False
        host.blocked = False

    def replace(self, old_host, new_host):
        with self._host_dict_lock:
            info = self._host_dict.get(old_host)

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

        with self._host_dict_lock:
            present = host in self._host_dict
            if present:
                host_ids = self._host_dict[host]['ids']

        if present:
            self.unlimit(host, direction)
            return host_ids

        return Limiter.HostLimitIDs(*self._create_ids())

    def _create_ids(self):
        """
        Returns unique IDs that are
        currently not in use
        """
        with self._host_dict_lock:
            used = {
                id_ for host_data in self._host_dict.values()
                for id_ in (host_data['ids'].upload_id, host_data['ids'].download_id)
            }

        id1 = 1
        while id1 in used:
            id1 += 1
        used.add(id1)

        id2 = id1 + 1
        while id2 in used:
            id2 += 1

        return (id1, id2)

    def _delete_tc_class(self, id_):
        """
        Deletes the tc class, attached SFQ leaf qdisc, and applied filters for a given ID (host)
        """
        for dev in (self.interface, 'ifb0'):
            shell.execute_suppressed('{} filter del dev {} parent 1:0 prio {}'.format(BIN_TC, dev, id_))
            shell.execute_suppressed('{} qdisc del dev {} parent 1:{}'.format(BIN_TC, dev, id_))
            shell.execute_suppressed('{} class del dev {} parent 1:0 classid 1:{}'.format(BIN_TC, dev, id_))

    def _delete_iptables_entries(self, host, direction, id_):
        """
        Deletes iptables rules for a given ID (host) cleanly without orphan rules
        """
        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            if host.mac:
                shell.execute_suppressed('{} -t mangle -D POSTROUTING -s {} -m mac --mac-source {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host.mac, id_))
                shell.execute_suppressed('{} -t filter -D FORWARD -s {} -m mac --mac-source {} -j DROP'.format(BIN_IPTABLES, host.ip, host.mac))
            shell.execute_suppressed('{} -t mangle -D POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
            shell.execute_suppressed('{} -t filter -D FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            shell.execute_suppressed('{} -t mangle -D PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
            shell.execute_suppressed('{} -t filter -D FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip))


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
