#! /bin/bash
turn_off_busypolling() {
    echo 0 | sudo tee "/sys/class/net/$NET_IFACE/napi_defer_hard_irqs"
    echo 0 | sudo tee "/sys/class/net/$NET_IFACE/gro_flush_timeout"
}

busypoll_budget=200000
turn_on_busypolling() {
    echo 2 | sudo tee "/sys/class/net/$NET_IFACE/napi_defer_hard_irqs"
    echo "$busypoll_budget" | sudo tee "/sys/class/net/$NET_IFACE/gro_flush_timeout"
}

on_signal() {
	running=0
}

trap 'on_signal' SIGINT SIGHUP

turn_on_busypolling
running=1
while [ $running -eq 1 ] ; do
	sleep 5
done
turn_off_busypolling
