#!/bin/bash

# NOTE: give the key to use for the test on the command line.
key="$1"
if [[ -z $key ]]; then
	echo "Please supply path to the (private) key, E.g.,"
	echo "    ./kem-test.sh /path/to/key"
	exit 1
fi

if [[ ! -d tests/data ]]; then
	mkdir tests/data
	echo "Place test files in tests/data/ before running this."
	exit 1
fi

# reuse temp directory if present.
tdir=$(ls -d /tmp/480-p1-tdata-* 2> /dev/null)
[[ -z $tdir ]] && tdir=$(mktemp -d /tmp/480-p1-tdata-XXX)
match=0
total=0
for f in tests/data/* ; do
	bn=${f##*/}
	./kem-enc -e -i "$f" -o "$tdir/${bn}.enc" -k "${1}.pub"
	./kem-enc -d -i "$tdir/${bn}.enc" -o "$tdir/${bn}" -k "$1"
	if diff "$f" "$tdir/${bn}" &>/dev/null ; then
		(( match++ ))
		echo $f :: pass
	else
		echo $f :: fail
	fi
	(( total++ ))
done
echo "$match out of $total files matched."
