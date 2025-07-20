#!/bin/bash
for x in $(ls); do
	o="${x%.*}.png";
	echo "$x --> $o.png";
	convert -density 120 $x $o;
done

