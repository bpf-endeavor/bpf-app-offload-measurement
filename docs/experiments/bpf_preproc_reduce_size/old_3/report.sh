#! /bin/bash

FILES=( )
VAL=( )
ERR=( )
for f in *_xdp_*.txt; do
	echo $f
	FILES+=( $f )
	T=$(cat $f  | awk '{print $2}' | ../../../latency_script.py  | grep +-)
	m=$(echo $T | awk '{print $4}')
	p=$(echo $T | awk '{print $6}')
	VAL+=( $m )
	ERR+=( $p )
done

echo ${FILES[@]}
echo ${VAL[@]}
echo ${ERR[@]}
