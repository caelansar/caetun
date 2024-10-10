#!/bin/bash

sudo setcap cap_net_admin=eip /home/caelansar/.cargo/bin/caetun

sudo /home/caelansar/.cargo/bin/caetun --conf server.conf &

usleep 100000

pid=$!

sudo ip addr add 10.8.0.1/24 dev server
sudo ip link set up dev server
sudo ip link set dev server mtu 1400

nc -l 10.8.0.1 8080 &
ncpid=$!

trap "kill $pid $ncpid" INT TERM

wait $pid
wait $ncpid
