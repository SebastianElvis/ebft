#!/bin/bash
num_blocks=$1
interval=$2
committee_size=$3

# change the working directory
cd "$(dirname "$0")"

# read address list as $x
mapfile -t x < address-list.txt

echo "$num_blocks blocks with interval $interval will be generated"

for i in $(seq $num_blocks)
do 
    r=$(($RANDOM % $committee_size))
    addr=${x[$r]}
    btcctl --simnet --rpcuser=USER --rpcpass=PASS generatetoaddress 1 $addr
    echo "Generated block #$i to the $r-th address $addr"
    i=$((i+1))
    x=$(python -c "import random;print(random.uniform(0.0, $interval*2))")
    sleep $x
done