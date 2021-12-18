num_blocks=$1
interval=$2

echo "$num_blocks blocks with interval $interval will be generated"

for i in $(seq $num_blocks)
do 
    echo "Generating block #$i"
    btcctl --simnet --rpcuser=USER --rpcpass=PASS generate 1
    i=$((i+1))
    sleep $2
done