#!/bin/bash
sysctl -w net.ipv4.ip_forward=1

while true
do
  sleep 10
done