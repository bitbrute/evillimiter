import time
import threading
from scapy.all import sniff, IP # pylint: disable=no-name-in-module

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

        self._host_result_dict = {}
        self._host_result_lock = threading.Lock()

        self._running = False

    def add(self, host):
        with self._host_result_lock:
            if host not in self._host_result_dict:
                self._host_result_dict[host] = { 'result': BandwidthMonitor.BandwidthMonitorResult(), 'last_now': time.time() }

    def remove(self, host):
        with self._host_result_lock:
            self._host_result_dict.pop(host, None)

    def replace(self, old_host, new_host):
        with self._host_result_lock:
            if old_host in self._host_result_dict:
                self._host_result_dict[new_host] = self._host_result_dict[old_host]
                del self._host_result_dict[old_host]

    def start(self):
        if self._running:
            return

        sniff_thread = threading.Thread(target=self._sniff, args=[], daemon=True)
        sniff_thread.start()

        self._running = True

    def stop(self):
        self._running = False

    def get(self, host):
        with self._host_result_lock:
            if host in self._host_result_dict:
                last_now = self._host_result_dict[host]['last_now']
                time_passed = time.time() - last_now
                result = self._host_result_dict[host]['result']
                result.upload_rate = BitRate(int(ValueConverter.byte_to_bit(result._upload_temp_size.value) / time_passed))
                result.download_rate = BitRate(int(ValueConverter.byte_to_bit(result._download_temp_size.value) / time_passed))

                result._upload_temp_size *= 0
                result._download_temp_size *= 0

                self._host_result_dict[host]['last_now'] = time.time()
                return result

    def _sniff(self):
        def pkt_handler(pkt):
            if pkt.haslayer(IP):
                with self._host_result_lock:
                    for host in self._host_result_dict:
                        result = self._host_result_dict[host]['result']
                        if host.ip == pkt[IP].src:
                            result.upload_total_size += len(pkt)
                            result.upload_total_count += 1
                            result._upload_temp_size += len(pkt)
                        elif host.ip == pkt[IP].dst:
                            result.download_total_size += len(pkt)
                            result.download_total_count += 1
                            result._download_temp_size += len(pkt)
                        
        def stop_filter(pkt):
            return not self._running

        sniff(iface=self.interface, prn=pkt_handler, stop_filter=stop_filter, store=0)
    