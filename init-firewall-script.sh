#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t filter -F
iptables -t nat -F 
iptables -t raw -F
iptables -t mangle -F
#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP  
iptables -A INPUT -p icmp -s 10.10.10.0/24 -d 10.10.10.254 -j ACCEPT  
iptables -A OUTPUT -p icmp -s 10.10.10.254 -d 10.10.10.0/24 -j ACCEPT
iptables -A INPUT -p icmp -s 192.168.10.0/24 -d 192.168.10.254 -j ACCEPT  
iptables -A OUTPUT -p icmp -s 192.168.10.254 -d 192.168.10.0/24 -j ACCEPT
iptables -t filter -A FORWARD -p icmp -s 192.168.10.0/24 -d 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD -p icmp -s 10.10.10.0/24 -d 192.168.10.0/24 --icmp-type echo-reply -j ACCEPT

#iptables -A FORWARD -p icmp -s 10.10.10.0/24 -d 192.168.10.0/24 --icmp-type echo-request -j REJECT
while true
do
  sleep 10
done