import evillimiter.console.shell as shell

BROADCAST = 'ff:ff:ff:ff:ff:ff'

BIN_TC = shell.locate_bin('tc')
BIN_IPTABLES = shell.locate_bin('iptables')
BIN_SYSCTL = shell.locate_bin('sysctl')

IP_FORWARD_LOC = 'net.ipv4.ip_forward'