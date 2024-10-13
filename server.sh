#!/bin/bash

setcap cap_net_admin=eip /usr/local/bin/caetun

/usr/local/bin/caetun --conf /etc/caetun/server.conf &

sleep 1

pid=$!

ip addr add 10.8.0.1/24 dev server
ip link set up dev server
ip link set dev server mtu 1400

trap "kill $pid $ncpid" INT TERM

wait $pid
