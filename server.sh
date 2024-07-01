#!/bin/bash

sudo setcap cap_net_admin=eip /home/caelansar/.cargo/bin/caetun

sudo /home/caelansar/.cargo/bin/caetun &

pid=$!

sudo ip addr add 10.8.0.1/24 dev tun0
sudo ip link set up dev tun0
sudo ip link set dev tun0 mtu 1400

nc -l 10.8.0.1 8080 &
ncpid=$!

trap "kill $pid $ncpid" INT TERM

wait $pid
wait $ncpid
