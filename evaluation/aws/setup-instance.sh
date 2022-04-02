#!/bin/bash

yum -y install cmake gcc m4 gmp gmp-devel mpfr mpfr-devel libmpc libmpc-devel dstat

wget -O /bin/btcd https://orazor-dev.s3.us-east-1.amazonaws.com/btcd
wget -O /bin/btcctl https://orazor-dev.s3.us-east-1.amazonaws.com/btcctl
wget -O /home/ec2-user/simulated-miner.sh https://orazor-dev.s3.us-east-1.amazonaws.com/simulated-miner.sh
wget -O /home/ec2-user/simulated-miner.sh https://orazor-dev.s3.us-east-1.amazonaws.com/simulated-random-miner.sh
wget -O /home/ec2-user/address-list.txt https://orazor-dev.s3.us-east-1.amazonaws.com/address-list.txt

chmod +x /bin/btcd
chmod 777 /bin/btcd
chown ec2-user /bin/btcd

chmod +x /bin/btcctl
chmod 777 /bin/btcctl
chown ec2-user /bin/btcctl

chmod +x /home/ec2-user/simulated-miner.sh
chmod 777 /home/ec2-user/simulated-miner.sh
chown ec2-user /home/ec2-user/simulated-miner.sh
chmod +x /home/ec2-user/simulated-random-miner.sh
chmod 777 /home/ec2-user/simulated-random-miner.sh
chown ec2-user /home/ec2-user/simulated-random-miner.sh

chmod 777 /home/ec2-user/address-list.txt
chown ec2-user /home/ec2-user/address-list.txt

echo '#!/bin/bash' >> /home/ec2-user/main.sh
echo 'dstat --integer --noupdate -T -n --tcp --cpu --mem --output /home/ec2-user/stats.csv 1 &> /dev/null &' >> /home/ec2-user/main.sh
# $1 extension, $2 committee-size, $3 latency, $4 mining addr, $5 minerblocksize, $6 epochsize $7.. all IP addresses (--connect=ip1:port1 --connect=ip2:port2 ...)
# --miningaddr is inserted in _run_command
echo 'nohup btcd --$1 -d info --committeesize=$2 --latency=$3 --nostalldetect -u USER -P PASS  --listen=0.0.0.0:18555 --rpclisten=0.0.0.0:18556 --miningaddr=$4 --minerblocksize=$5 --epochsize=$6 ${@:7} > /home/ec2-user/main.log 2>&1 &' >> /home/ec2-user/main.sh
chmod +x /home/ec2-user/main.sh
chmod 777 /home/ec2-user/main.sh
chown ec2-user /home/ec2-user/main.sh
