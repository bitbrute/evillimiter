import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES


class Limiter(object):
    def __init__(self, interface):
        self.interface = interface

        # maps an ID to each host to destinguish between the forwarded packets
        self.host_id_map = {}

    def limit(self, host: Host, rate):
        """
        Limits the uload/dload traffic of a host
        to a specified rate
        """
        id_ = self._create_id()

        if host in self.host_id_map:
            id_ = self.host_id_map[host]
            self.unlimit(host)

        # add a class to the root qdisc with specified rate
        shell.execute_suppressed('{} class add dev {} parent 1:0 classid 1:{} htb rate {r} ceil {r}'.format(BIN_TC, self.interface, id_, r=rate))
        # add a fw filter that filters packets marked with the corresponding ID
        shell.execute_suppressed('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(BIN_TC, self.interface, id=id_))

        # marks outgoing packets 
        shell.execute_suppressed('{} -t mangle -A POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
        # marks incoming packets
        shell.execute_suppressed('{} -t mangle -A PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))

        self.host_id_map[host] = id_
        host.limited = True

    def block(self, host):
        id_ = self._create_id()

        if host in self.host_id_map:
            id_ = self.host_id_map[host]
            self.unlimit(host)

        # drops forwarded packets with matching source
        shell.execute_suppressed('{} -t filter -A FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
        # drops forwarded packets with matching destination
        shell.execute_suppressed('{} -t filter -A FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip))

        self.host_id_map[host] = id_
        host.blocked = True

    def unlimit(self, host):
        id_ = self.host_id_map[host]
        self._delete_tc_class(id_)
        self._delete_iptables_entries(host, id_)

        del self.host_id_map[host]
        host.limited = False
        host.blocked = False

    def _create_id(self):
        """
        Returns a unique ID that is
        currently not in use
        """
        id_ = 1
        while True:
            if id_ not in self.host_id_map.values():
                return id_
            id_ += 1

    def _delete_tc_class(self, id_):
        """
        Deletes the tc class and applied filters
        for a given ID (host)
        """
        shell.execute_suppressed('{} filter del dev {} parent 1:0 prio {}'.format(BIN_TC, self.interface, id_))
        shell.execute_suppressed('{} class del dev {} parent 1:0 classid 1:{}'.format(BIN_TC, self.interface, id_))

    def _delete_iptables_entries(self, host: Host, id_):
        """
        Deletes iptables rules for a given ID (host)
        """
        shell.execute_suppressed('{} -t mangle -D POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
        shell.execute_suppressed('{} -t mangle -D PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_))
        shell.execute_suppressed('{} -t filter -D FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip))
        shell.execute_suppressed('{} -t filter -D FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip))