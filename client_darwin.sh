#!/bin/bash
CONF=$1

echo "CONF: $CONF"

ADDR=$(./target/release/caetun-conf --conf $CONF | jq -r '"\(.interface.address[0])"')
IP=$(./target/release/caetun-conf --conf $CONF | jq -r '"\(.interface.address[0])/\(.interface.address[1])"')

./target/release/caetun --conf $CONF &

sleep 1

pid=$!

sudo ifconfig utun8 $ADDR $ADDR netmask 255.255.255.0
sudo ifconfig utun8 up
sudo ifconfig utun8 mtu 1400

sudo route add -net $IP -interface utun8

wait $pid