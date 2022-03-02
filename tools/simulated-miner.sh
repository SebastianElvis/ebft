endpoint=$1
num_blocks=$2
interval=$3

echo "$num_blocks blocks with interval $interval will be generated"

for i in $(seq $num_blocks)
do 
    echo "Generating block #$i"
    btcctl --simnet --rpcserver=$1 --rpcuser=USER --rpcpass=PASS generate 1
    i=$((i+1))
    sleep $3
done