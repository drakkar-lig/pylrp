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

