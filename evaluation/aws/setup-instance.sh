#!/bin/bash

yum -y install cmake gcc m4 gmp gmp-devel mpfr mpfr-devel libmpc libmpc-devel dstat

wget -O /bin/btcd https://orazor-dev.s3.us-east-1.amazonaws.com/btcd
chmod +x /bin/btcd
chmod 777 /bin/btcd
chown ec2-user /bin/btcd

echo '#!/bin/bash' >> /home/ec2-user/main.sh
echo 'dstat --integer --noupdate -T -n --tcp --cpu --mem --output /home/ec2-user/stats.csv 1 &> /dev/null &' >> /home/ec2-user/main.sh
# $1 extension, $2 committee-size, $3 latency, $4 all IP addresses (--connect ip1:port1 --connect ip2:port2 ...)
# --miningaddr is inserted in _run_command
echo 'nohup btcd --$1  -d debug --committeesize=$2 --latency=$3 --nostalldetect -u USER -P PASS --rpclisten=0.0.0.0:18556 $4> /home/ec2-user/main.log 2>&1 &' >> /home/ec2-user/main.sh
chmod +x /home/ec2-user/main.sh
chmod 777 /home/ec2-user/main.sh
chown ec2-user /home/ec2-user/main.sh
