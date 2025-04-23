#!/bin/bash

# Assumption: the af_xdp app is open on the server

APP=/home/farbod/dpdk-client-server/build/app
REPEAT=100
SERVER=138.37.32.108
SSH_USER=farbod

for i in $(seq $REPEAT); do
        echo $i
        sudo $APP -a $NET_PCI --lcores "0@(2,4)" -- \
                --client --ip-local 192.168.200.102 \
                --ip-dest 192.168.200.101 --rate 8000
        sleep 1
        # Send a signal to the AF_XDP app
        ssh $SSH_USER@$SERVER << EOF
sudo kill -SIGUSR1 \$(pidof xdpsock)
EOF
sleep 1
done

