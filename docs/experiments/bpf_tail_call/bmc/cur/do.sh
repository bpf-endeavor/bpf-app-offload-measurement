for x in $(ls *.txt); do
	echo '---------------------------------------------'
	echo $x
	cat $x | grep QPS | awk '{ print $4 / 1000000 }' | python3 ./stats.py
done
