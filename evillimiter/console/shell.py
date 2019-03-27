import subprocess

from evillimiter.common.globals import DEVNULL


def execute(command, root=True):
    return subprocess.call('sudo ' + command if root else command, shell=True)


def execute_suppressed(command, root=True):
    return subprocess.call('sudo ' + command if root else command, shell=True, stdout=DEVNULL, stderr=DEVNULL)