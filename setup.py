from setuptools import setup, find_packages
import os

def get_init_variable(var_name):
    init_path = os.path.join(os.path.dirname(__file__), 'evillimiter', '__init__.py')
    with open(init_path, 'r') as f:
        for line in f:
            if line.startswith(f'__{var_name}__'):
                return line.split('=')[1].strip().strip("'\"")
    return ''

setup(
    name='evillimiter',
    version=get_init_variable('version') or '1.6.0',
    description=get_init_variable('description') or 'Monitors, analyzes and limits the bandwidth of devices on the local network',
    author='bitbrute',
    url='https://github.com/bitbrute/evillimiter',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'terminaltables',
        'colorama',
        'scapy',
        'netifaces',
        'netaddr',
        'tqdm'
    ],
    entry_points={
        'console_scripts': [
            'evillimiter = evillimiter.evillimiter:run'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
)
