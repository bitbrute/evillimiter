from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac.lower() if mac else mac
        self.name = name
        self.vendor = ''
        self.spoofed = False
        self.limited = False
        self.blocked = False
        self.watched = False
        self.ipv6_killed = False

    def __eq__(self, other):
        if isinstance(other, Host):
            # Primary: compare by MAC (stable across IP changes)
            # Fallback: also match by IP for manually added hosts
            return self.mac.lower() == other.mac.lower() or self.ip == other.ip
        return False

    def __hash__(self):
        return hash(self.mac.lower())

    def pretty_status(self):
        if self.limited:
            return '{}Limited{}'.format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        elif self.blocked:
            return '{}Blocked{}'.format(IO.Fore.RED, IO.Style.RESET_ALL)
        else:
            return 'Free'