#!/usr/bin/env python3

from distutils.core import setup

setup(name='pylrp',
      version='0.0',
      description="Implementation of the LRP routing protocol",
      author="Henry-Joseph Audéoud",
      author_email="henry-joseph.audeoud@univ-grenoble-alpes.fr",
      url="https://gitlab.imag.fr/audeoudh/pylrp",
      packages=['lrp'], package_dir={'': 'src'},
      install_requires=['click', 'pyroute2', 'python-iptables', 'NetfilterQueue', 'scapy-python3', 'docker',
                        'networkx'])
