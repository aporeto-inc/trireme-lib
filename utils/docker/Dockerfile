FROM ubuntu
MAINTAINER Bernard Van De Walle <bernard@aporeto.com>

RUN mkdir -p /opt/trireme
RUN apt-get update && apt-get install -y \
    libnetfilter-queue1 \
    iptables \
&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD trireme /opt/trireme/trireme
ADD run.sh /opt/trireme/run.sh

WORKDIR /opt/trireme
CMD ./run.sh
