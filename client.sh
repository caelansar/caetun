#!/bin/bash
CONF=$1

echo "CONF: $CONF"

setcap cap_net_admin=eip /usr/local/bin/caetun

cp $CONF tun0.conf

IP=$(caetun-conf --conf tun0.conf | jq -r '"\(.interface.address[0])/\(.interface.address[1])"')

# the client script tells caetun exactly where to find its
# server peer, in this case at 198.19.249.106:19988
/usr/local/bin/caetun --conf tun0.conf &

sleep 1

pid=$!

ip addr add $IP dev tun0
ip link set up dev tun0
ip link set dev tun0 mtu 1400

trap "kill $pid" INT TERM

wait $pid
