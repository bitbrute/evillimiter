from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.spoofed = False
        self.limited = False
        self.blocked = False
        
    def pretty_status(self):
        if self.limited:
            return f'{IO.Fore.LIGHTRED_EX}Limited{IO.Style.RESET_ALL}'
        elif self.blocked:
            return f'{IO.Fore.RED}Blocked{IO.Style.RESET_ALL}'
        else:
            return 'Free'