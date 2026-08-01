import os
import re
import socket
import struct
import time
import threading

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_IPTABLES, BIN_TC
from .utils import ValueConverter, BitRate, ByteValue


class BandwidthMonitor(object):
    class BandwidthMonitorResult(object):
        def __init__(self):
            self.upload_rate = BitRate()
            self.upload_total_size = ByteValue()
            self.upload_total_count = 0
            self.download_rate = BitRate()
            self.download_total_size = ByteValue()
            self.download_total_count = 0

            self._upload_temp_size = ByteValue()
            self._download_temp_size = ByteValue()

    def __init__(self, interface, interval):
        self.interface = interface
        self.interval = interval

        self._host_result_dict = {}
        self._ip_to_host_map = {}
        self._host_result_lock = threading.Lock()

        self._running = False
        self._socket = None

    def add(self, host):
        with self._host_result_lock:
            if host not in self._host_result_dict:
                self._host_result_dict[host] = { 'result': BandwidthMonitor.BandwidthMonitorResult(), 'last_now': time.time() }
                self._ip_to_host_map[host.ip] = host

    def remove(self, host):
        with self._host_result_lock:
            if host in self._host_result_dict:
                self._host_result_dict.pop(host, None)
                self._ip_to_host_map.pop(host.ip, None)

    def replace(self, old_host, new_host):
        with self._host_result_lock:
            if old_host in self._host_result_dict:
                self._host_result_dict[new_host] = self._host_result_dict[old_host]
                del self._host_result_dict[old_host]
                self._ip_to_host_map.pop(old_host.ip, None)
                self._ip_to_host_map[new_host.ip] = new_host

    def start(self):
        if self._running:
            return

        self._running = True
        sniff_thread = threading.Thread(target=self._fast_sniff, args=[], daemon=True)
        sniff_thread.start()

    def stop(self):
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def get(self, host):
        # 1. Try querying kernel-level iptables/tc statistics if available
        kernel_result = self._query_kernel_stats(host)
        if kernel_result is not None:
            return kernel_result

        # 2. Fallback to high-speed raw socket capture stats
        with self._host_result_lock:
            if host in self._host_result_dict:
                last_now = self._host_result_dict[host]['last_now']
                time_passed = time.time() - last_now
                result = self._host_result_dict[host]['result']
                result.upload_rate = BitRate(int(ValueConverter.byte_to_bit(result._upload_temp_size.value) / time_passed)) if time_passed > 0 else BitRate(0)
                result.download_rate = BitRate(int(ValueConverter.byte_to_bit(result._download_temp_size.value) / time_passed)) if time_passed > 0 else BitRate(0)

                result._upload_temp_size *= 0
                result._download_temp_size *= 0

                self._host_result_dict[host]['last_now'] = time.time()
                return result

    def _query_kernel_stats(self, host):
        """
        Retrieves hardware/kernel byte statistics directly from iptables mangle rules
        """
        try:
            raw_output = shell.output_suppressed('{} -t mangle -L -v -n -x'.format(BIN_IPTABLES))
            if not raw_output:
                return None

            up_bytes, down_bytes = 0, 0
            for line in raw_output.splitlines():
                line = line.strip()
                if line.startswith('#') or line.startswith('iptables') or not line:
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    # pkts, bytes, target, prot, opt, in, out, src, dst
                    b_count = int(parts[1]) if parts[1].isdigit() else 0
                    src = parts[7]
                    dst = parts[8]

                    if src.startswith(host.ip):
                        up_bytes += b_count
                    elif dst.startswith(host.ip):
                        down_bytes += b_count

            if up_bytes > 0 or down_bytes > 0:
                with self._host_result_lock:
                    if host in self._host_result_dict:
                        last_now = self._host_result_dict[host]['last_now']
                        time_passed = time.time() - last_now
                        result = self._host_result_dict[host]['result']
                        
                        delta_up = max(0, up_bytes - result.upload_total_size.value)
                        delta_down = max(0, down_bytes - result.download_total_size.value)

                        result.upload_rate = BitRate(int(ValueConverter.byte_to_bit(delta_up) / time_passed)) if time_passed > 0 else BitRate(0)
                        result.download_rate = BitRate(int(ValueConverter.byte_to_bit(delta_down) / time_passed)) if time_passed > 0 else BitRate(0)

                        result.upload_total_size = ByteValue(up_bytes)
                        result.download_total_size = ByteValue(down_bytes)
                        self._host_result_dict[host]['last_now'] = time.time()
                        return result
        except Exception:
            pass

        return None

    def _fast_sniff(self):
        """
        Zero-copy lightweight raw socket packet header parser.
        Bypasses Scapy object instantiation overhead.
        """
        if hasattr(socket, 'AF_PACKET'):
            try:
                # ETH_P_IP = 0x0800 (big-endian 0x0008)
                self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
                self._socket.bind((self.interface, 0))
                self._socket.settimeout(0.5)
            except Exception:
                self._socket = None

        if self._socket:
            while self._running:
                try:
                    raw_pkt = self._socket.recv(2048)
                    if len(raw_pkt) >= 34:
                        # Extract source and destination IPv4 addresses from raw bytes
                        src_ip = socket.inet_ntoa(raw_pkt[26:30])
                        dst_ip = socket.inet_ntoa(raw_pkt[30:34])
                        pkt_len = len(raw_pkt)

                        with self._host_result_lock:
                            src_host = self._ip_to_host_map.get(src_ip)
                            if src_host and src_host in self._host_result_dict:
                                res = self._host_result_dict[src_host]['result']
                                res.upload_total_size += pkt_len
                                res.upload_total_count += 1
                                res._upload_temp_size += pkt_len

                            dst_host = self._ip_to_host_map.get(dst_ip)
                            if dst_host and dst_host in self._host_result_dict:
                                res = self._host_result_dict[dst_host]['result']
                                res.download_total_size += pkt_len
                                res.download_total_count += 1
                                res._download_temp_size += pkt_len
                except socket.timeout:
                    continue
                except Exception:
                    time.sleep(0.01)
        else:
            # Fallback to Scapy sniff if AF_PACKET is unavailable
            try:
                from scapy.all import sniff, IP
                def pkt_handler(pkt):
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        pkt_len = len(pkt)

                        with self._host_result_lock:
                            src_host = self._ip_to_host_map.get(src_ip)
                            if src_host and src_host in self._host_result_dict:
                                result = self._host_result_dict[src_host]['result']
                                result.upload_total_size += pkt_len
                                result.upload_total_count += 1
                                result._upload_temp_size += pkt_len

                            dst_host = self._ip_to_host_map.get(dst_ip)
                            if dst_host and dst_host in self._host_result_dict:
                                result = self._host_result_dict[dst_host]['result']
                                result.download_total_size += pkt_len
                                result.download_total_count += 1
                                result._download_temp_size += pkt_len

                def stop_filter(pkt):
                    return not self._running

                sniff(iface=self.interface, filter='ip', prn=pkt_handler, stop_filter=stop_filter, store=0)
            except Exception:
                pass
    