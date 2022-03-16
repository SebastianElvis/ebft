#!/bin/bash

ssh -i "~/.ssh/orazor.pem" -oStrictHostKeyChecking=accept-new -l ec2-user $1
