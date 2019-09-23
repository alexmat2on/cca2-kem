#!/bin/bash

# test everything.

# first the basic rsa and ske tests:

./tests/rsa-test &> output
./tests/ske-test &>> output

# set up some test files:
mkdir -p ./tests/data
sizes="64 77 129 273 591"
for n in $sizes ; do
	[[ ! -f ./tests/data/T$n ]] && \
		head -c $n < /dev/urandom | xxd > ./tests/data/T$n
done

# now make a key:
rm -f /tmp/testkey*
./kem-enc -b 2048 -g /tmp/testkey

./kem-test.sh /tmp/testkey >> output

