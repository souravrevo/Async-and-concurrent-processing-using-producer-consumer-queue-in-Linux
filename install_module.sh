#!/bin/sh
gcc xhw3.c -o xhw3
make
rmmod sys_xjob
insmod sys_xjob.ko
