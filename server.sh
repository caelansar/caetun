#!/bin/bash

setcap cap_net_admin=eip /usr/local/bin/caetun

/usr/local/bin/caetun --conf /etc/caetun/server.conf &

sleep 1

pid=$!

ip addr add 10.8.0.1/24 dev server
ip link set up dev server
ip link set dev server mtu 1400

iptables -A INPUT -j NFLOG --nflog-prefix "Input packet: " --nflog-group 1
iptables -A FORWARD -j NFLOG --nflog-prefix "Packet forwarded: " --nflog-group 1

trap "kill $pid" INT TERM

wait $pid
