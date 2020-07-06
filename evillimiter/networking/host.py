from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.spoofed = False
        self.limited = False
        self.blocked = False
        self.watched = False

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash((self.mac, self.ip))