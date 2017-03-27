#!/bin/bash

# variabile
SSH_PORT=22
###

yum install iptables-services -y

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A FORWARD -i lo -j ACCEPT

# allow established
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT 2 -p icmp --icmp-type echo-request -j ACCEPT

# allow ssh
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "SSH"
iptables -A OUTPUT -p tcp --dport $SSH_PORT -m state --state ESTABLISHED -j ACCEPT -m comment --comment "SSH"

# allow stuff
iptables -A INPUT -p tcp --dport 24 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "lmtp"
iptables -A INPUT -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "smtp"
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "http"
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "https"
iptables -A INPUT -p tcp --dport 465 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "smtps"
iptables -A INPUT -p tcp --dport 587 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "smtp-msa"
iptables -A INPUT -p tcp --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "pop3"
iptables -A INPUT -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "imap"
iptables -A INPUT -p tcp --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "imaps"
iptables -A INPUT -p tcp --dport 995 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "pops"
iptables -A INPUT -p tcp --dport 1025 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "amavis"
iptables -A INPUT -p tcp --dport 8891 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "opendkim"
iptables -A INPUT -p tcp --dport 4190 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "dovecot-sieve"
iptables -A INPUT -p tcp --dport 25357 -m state --state NEW,ESTABLISHED -j ACCEPT -m comment --comment "quota-status"

#iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
#iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited

iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP

service iptables save
systemctl restart iptables
#systemctl enable iptables
