#!/bin/bash

if [[ ! -d data ]]; then
	mkdir data
	echo "Place test files in data/ before running this."
	exit 1
fi

# reuse temp directory if present.
tdir=$(ls -d /tmp/ske-tdata-* 2> /dev/null)
[[ -z $tdir ]] && tdir=$(mktemp -d /tmp/ske-tdata-XXX)
match=0
total=0
for f in data/* ; do
	bn=${f##*/}
	./ske-test "$f" "$tdir/${bn}.enc" "$tdir/${bn}"
	if diff "$f" "$tdir/${bn}" ; then
		(( match++ ))
	fi
	(( total++ ))
done
echo "$match out of $total files matched."
