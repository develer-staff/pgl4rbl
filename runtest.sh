#!/bin/bash
GREYLIST_DB=/tmp/pgl4rbl

if [ ! -d "$GREYLIST_DB" ]; then
	echo $GREYLIST_DB does not exist
	exit 2
fi

find $GREYLIST_DB -type f -exec rm {} \;

python pgl4rbl.py < test/test.in > /tmp/test.out.$$
diff test/test.out /tmp/test.out.$$

