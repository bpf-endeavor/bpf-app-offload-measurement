#! /bin/bash

function calculate {
	cat $TMP_FILE | awk '{ x+=$1; y+=1 } END { print "Avg: "  x/y }'
	COUNT_LINES=`cat $TMP_FILE | wc -l`
	TAIL_LINE=`echo "$COUNT_LINES * 0.99" | bc | xargs -I {} printf "%.0f" {}`
	# echo "$COUNT_LINES --> $TAIL_LINE"
	TAIL_VAL=`head -n $TAIL_LINE $TMP_FILE | tail -n 1`
	printf "@99: %f\n" $TAIL_VAL
}

FILE=$1
TMP_FILE=/tmp/tmp.txt
echo "Processing file: $FILE"

echo "Parser Timestamps:"
# Select parser values and sort
cat $FILE | cut -d ',' -f 1 | sort -n > $TMP_FILE
calculate

echo "Verdict Timestamps:"
# Select verdict values and sort
cat $FILE | cut -d ',' -f 2 | sort -n > $TMP_FILE
calculate
