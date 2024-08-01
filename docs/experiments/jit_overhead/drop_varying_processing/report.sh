#! /bin/bash
function report {
	dir=$1
	x=( 0 2 4 8 16 32 64 128 256 )
	y=( )
	for v in ${x[@]}; do
		file="$dir/${v}_csum.txt"
		t=$(cat $file | grep throughput | awk '{print ($(NF - 1) / 1000000)}' | ../../../latency_script.py | grep +- | awk '{print $4}')
		y+=($t)
	done
	echo "x: [$(echo ${x[@]} | tr ' ' ',')]"
	echo "y: [$(echo ${y[@]} | tr ' ' ',')]"
}

echo "XDP: "
report ./xdp

echo "Native:"
report ./native
