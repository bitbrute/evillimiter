import subprocess


def execute(command, root=True):
    return subprocess.call('sudo ' + command if root else command, shell=True)


def execute_suppressed(command, root=True):
    return subprocess.call(
        'sudo ' + command if root else command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def output(command, root=True):
    return subprocess.check_output('sudo ' + command if root else command, shell=True).decode('utf-8')


def output_suppressed(command, root=True):
    return subprocess.check_output('sudo ' + command if root else command, shell=True, stderr=subprocess.DEVNULL).decode('utf-8')


def locate_bin(name):
    try:
        return output_suppressed('which {}'.format(name)).replace('\n', '')
    except subprocess.CalledProcessError:
        from evillimiter.console.io import IO
        IO.error('missing util: {}, check your PATH'.format(name))