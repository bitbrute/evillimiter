import os


DEVNULL = open(os.devnull, 'w')
BROADCAST = 'ff:ff:ff:ff:ff:ff'

BIN_TC = '/sbin/tc'
BIN_IPTABLES = '/sbin/iptables'
BIN_SYSCTL = '/sbin/sysctl'

IP_FORWARD_LOC = 'net.ipv4.ip_forward'