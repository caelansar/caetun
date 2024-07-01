#!/bin/bash

sudo setcap cap_net_admin=eip /usr/local/bin/caetun

# the client script tells caetun exactly where to find its
# server peer, in this case at 198.19.249.106:19988
sudo /usr/local/bin/caetun --peer 198.19.249.106:19988 &

pid=$!

sudo ip addr add 10.8.0.2/24 dev tun0
sudo ip link set up dev tun0
sudo ip link set dev tun0 mtu 1400

trap "kill $pid" INT TERM

wait $pid
