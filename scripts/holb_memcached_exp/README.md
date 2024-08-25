# Scenario 1

Run two Memcached instances. One is accelerated by BMC and one is not. BMC
offload will cause HOLB.

scripts: [run_servers.sh, duo_run.sh]

# Scenario 2

Run one Memcached instance. There is a background flow that alway is processed
in BMC. The flow that is used for measurment is processed in Memcached because
its value size is 1100 bytes and BMC can not handle it.

scripts: [run_server_v2.sh, tre_run.sh]

