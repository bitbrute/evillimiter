import time
import threading


class HostWatcher(object):
    def __init__(self, host_scanner, reconnection_callback):
        self._scanner = host_scanner
        self._reconnection_callback = reconnection_callback
        self._hosts = set()
        self._hosts_lock = threading.Lock()

        self._interval = 45     # scan interval in s
        self._iprange = None    # custom ip range to be watched
        self._settings_lock = threading.Lock()

        self._log_list = []
        self._log_list_lock = threading.Lock()

        self._running = False

    @property
    def interval(self):
        with self._settings_lock:
            return self._interval

    @interval.setter
    def interval(self, value):
        with self._settings_lock:
            self._interval = value

    @property
    def iprange(self):
        with self._settings_lock:
            return self._iprange

    @iprange.setter
    def iprange(self, value):
        with self._settings_lock:
            self._iprange = value

    @property
    def hosts(self):
        with self._hosts_lock:
            return self._hosts.copy()

    @property
    def log_list(self):
        with self._log_list_lock:
            return self._log_list.copy()

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)

        host.watched = True

    def remove(self, host):
        with self._hosts_lock:
            self._hosts.discard(host)

        host.watched = False

    def start(self):
        thread = threading.Thread(target=self._watch, args=[], daemon=True)
        
        self._running = True
        thread.start()

    def stop(self):
        self._running = False

    def _watch(self):
        while self._running:
            self._hosts_lock.acquire()
            hosts = self._hosts.copy()
            self._hosts_lock.release()

            if len(hosts) > 0:
                reconnected_hosts = self._scanner.scan_for_reconnects(hosts, self.iprange)
                for old_host, new_host in reconnected_hosts.items():
                    self._reconnection_callback(old_host, new_host)
                    with self._log_list_lock:
                        self._log_list.append({ 'old': old_host, 'new': new_host, 'time': time.strftime('%Y-%m-%d %H:%M %p') })

            time.sleep(self.interval)