Running memcached

    taskset -c 1 ./memcached -U 11211 -l 192.168.200.101 -m 1024 -M -k -t 1 -C

