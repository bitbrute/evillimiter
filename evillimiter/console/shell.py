import os
import subprocess
import shutil
from evillimiter.console.io import IO


def _format_command(command, root=True):
    if root and hasattr(os, 'geteuid') and os.geteuid() != 0:
        return 'sudo ' + command
    return command


def execute(command, root=True):
    return subprocess.call(_format_command(command, root), shell=True)


def execute_suppressed(command, root=True):
    return subprocess.call(_format_command(command, root), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def output(command, root=True):
    return subprocess.check_output(_format_command(command, root), shell=True).decode('utf-8')


def output_suppressed(command, root=True):
    return subprocess.check_output(_format_command(command, root), shell=True, stderr=subprocess.DEVNULL).decode('utf-8')


def locate_bin(name):
    candidates = [name]
    if name == 'iptables':
        candidates = ['iptables-legacy', 'iptables', 'iptables-nft']

    sys_paths = ['/sbin', '/usr/sbin', '/usr/local/sbin', '/bin', '/usr/bin', '/usr/local/bin']
    current_path = os.environ.get('PATH', '')
    search_path = os.pathsep.join(current_path.split(os.pathsep) + sys_paths)

    for cand in candidates:
        bin_path = shutil.which(cand, path=search_path)
        if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
            return bin_path

        for sys_dir in sys_paths:
            full_path = os.path.join(sys_dir, cand)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path

    try:
        res = output_suppressed('which {}'.format(name)).strip()
        if res:
            return res
    except Exception:
        pass

    IO.error('missing util: {}, check your PATH or install iptables/iproute2 (e.g. sudo apt install iptables iproute2)'.format(name))
    return name