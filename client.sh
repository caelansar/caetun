#!/bin/bash

sudo setcap cap_net_admin=eip /usr/local/bin/caetun

# the client script tells caetun exactly where to find its
# server peer, in this case at 198.19.249.106:19988
sudo /usr/local/bin/caetun --conf client.conf &

usleep 100000

pid=$!

sudo ip addr add 10.8.0.2/24 dev client
sudo ip link set up dev client
sudo ip link set dev client mtu 1400

trap "kill $pid" INT TERM

wait $pid
