qid=26
threads=4
curdir=$(dirname "$0")
sudo $curdir/../src/build/cache --threads $threads $NET_IFACE $qid
