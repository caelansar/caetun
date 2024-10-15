sudo ifconfig utun8 10.8.0.1 10.8.0.1 netmask 255.255.255.0
sudo ifconfig utun8 up
sudo ifconfig utun8 mtu 1400

sudo route add -net 10.8.0.0/24 -interface utun8