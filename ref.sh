#!/bin/bash

cp -r /mnt .
cd mnt/kernel-module
make clean
make
insmod hashtable.ko 
cd ../parser
./firewall
rmmod hashtable
dmesg