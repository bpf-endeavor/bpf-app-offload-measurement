#! /bin/bash
FILE=$1
echo "Processing file: $FILE"
cat $FILE | awk '{ x+=$1; y+=1 } END { print "Avg: "  x/y }'
COUNT_LINES=`cat $FILE | wc -l`
TAIL_LINE=`echo "$COUNT_LINES * 0.99" | bc | xargs -I {} printf "%.0f" {}`
# echo "$COUNT_LINES --> $TAIL_LINE"
TAIL_VAL=`head -n $TAIL_LINE $FILE | tail -n 1`
printf "@99: %f\n" $TAIL_VAL
