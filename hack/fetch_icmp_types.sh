#!/usr/bin/env bash
set -euo pipefail

iptables -p icmp -h | grep -A 1000 "Valid ICMP Types:" | tail -n +2
ip6tables -p icmpv6 -h | grep -A 1000 "Valid ICMPv6 Types:" | tail -n +2
