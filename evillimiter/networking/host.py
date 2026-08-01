from typing import Optional
from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip: str, mac: str, name: Optional[str] = ''):
        self.ip: str = ip
        self.mac: str = mac
        self.name: str = name or ''
        self.spoofed: bool = False
        self.limited: bool = False
        self.blocked: bool = False
        self.watched: bool = False

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Host):
            return self.ip == other.ip
        return False

    def __hash__(self) -> int:
        return hash(self.ip)

    def pretty_status(self) -> str:
        if self.limited:
            return '{}Limited{}'.format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        elif self.blocked:
            return '{}Blocked{}'.format(IO.Fore.RED, IO.Style.RESET_ALL)
        else:
            return 'Free'