# Copyright Laboratoire d'Informatique de Grenoble (2017)
#
# This file is part of pylrp.
#
# Pylrp is a Python/Linux implementation of the LRP routing protocol.
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/ or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

FROM base/archlinux

COPY 'python-pyroute2-0.4.17-1-any.pkg.tar.xz' \
     'python-iptables-0.12.0-1-any.pkg.tar.xz' \
     'python-netfilterqueue-git-r66.3fa8a38-1-any.pkg.tar.xz' \
     '/var/cache/pacman/pkg/'
RUN pacman -Syu --noconfirm sed gzip grep vim \
                            procps-ng \
                            iputils tcpdump net-tools iproute2 openbsd-netcat \
                            python python-click scapy3k && \
    pacman -U --noconfirm /var/cache/pacman/pkg/python-pyroute2-0.4.17-1-any.pkg.tar.xz \
                          /var/cache/pacman/pkg/python-iptables-0.12.0-1-any.pkg.tar.xz \
                          /var/cache/pacman/pkg/python-netfilterqueue-git-r66.3fa8a38-1-any.pkg.tar.xz

RUN sed -i s/^\#fr_FR.UTF-8/fr_FR.UTF-8/ /etc/locale.gen && locale-gen
RUN echo '43       lrp' >> /etc/iproute2/rt_protos  # Declare LRP as a known protocol


VOLUME /root/pylrp
WORKDIR /root/
ENTRYPOINT /bin/bash

