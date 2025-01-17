#!/bin/bash

AWS_REGIONS=(
    ap-northeast-1
    ap-northeast-2
    ap-south-1
    ap-southeast-1
    ap-southeast-2
    ca-central-1
    eu-central-1
    eu-west-1
    eu-west-2
    sa-east-1
    us-east-1
    us-east-2
    us-west-1
    us-west-2
)

for each in ${AWS_REGIONS}
do
    aws ec2 import-key-pair --key-name orazor --public-key-material file://~/.ssh/orazor.pub --region $each
done
