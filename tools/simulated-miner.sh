endpoint=$1
num_blocks=$2
interval=$3
committee_size=$4

# read address list as $x
mapfile -t x < address-list.txt

echo "$num_blocks blocks with interval $interval will be generated"

for i in $(seq $num_blocks)
do 
    r=$((1 + $RANDOM % $committee_size))
    addr=${x[$r]}
    btcctl --simnet --rpcserver=$1 --rpcuser=USER --rpcpass=PASS generatetoaddress 1 $addr
    echo "Generated block #$i to address $addr"
    i=$((i+1))
    sleep $3
done