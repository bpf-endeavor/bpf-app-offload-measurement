qid=26
threads=4
curdir=$(dirname $0)
# if the environment is setup correctly the BMC binary should be at this
# directory. set the path manually if you need a different version of bmc or
# if the binary is not found
bmc="$curdir"/../../others/bmc_bins/original/bmc_kern.o
sudo ../src/build/cache --xdp-prog $bmc --threads $threads --bmc $NET_IFACE $qid

