# About

I have measured the latency of echoing a request at different levels (Socket, XDP, TC, SK\_SKB).
The client in `../holb_memcached_exp/sock_memcd/load_generator/` was used.
command: `timeout -s INT 20 taskset -c 11 ./main`

`server_bound` and `bpf_redirect.o` was used for echoing the requests.
