# mail_srv
config-script
"postfix+dovecot+mariadb(Quota)+amavisd(sa+clam)"

* First patch Postfix with VDA_patch, from here:
http://vda.sourceforge.net/

1)
installed 
	- postfix_VDA manual-update??? 
	- postfixadmin (web -> update???)
	- Dovecot -yum update
	- MariaDB (MySQL) -yum update
	- roundcube -yum update
	- amavis-new -yum update  (includes sa+clam)
		 - spamassasin -yum update (/etc/cron.d/sa-update)
		 - clamAV -yum update 
	- apache2.4+ -yum update
	- policy SPF -yum update
	- opendkim -yum update
	- mod_ssl -yum update (certificate creation)

2)
setat DKIM + postfix 	
  -DMARC add TXT DNS record
 
 3)
Apache 2.4 latest - settings
mod_security = apache protection: protect from sql injection
	-virtual_host = roundcube-$
			apache redirect *80 -> 443
			roundcubemail/installer = deny frm all (403 error)
	-virtual_host = postfixadmin-$ 
			apache redirect *80 -> 443
scripted SSL certificates = /etc/httpd/ssl/*

4)
- scripted roundcube install + config + mysql_DB + SQL entry
- scripted postfixadmin install + config + mysql_DB 

5)
postfix:::setup
+ virtual MAPS 
	  mysql_virtual_alias_maps.cf  
	  mysql_virtual_domains_maps.cf  
	  mysql_virtual_mailbox_maps.cf 
	  mysql_virtual_mailbox_limit_maps.cf
+ /etc/postfix/main.cf
+ /etc/postfix/master.cf

6)
dovecot:::setup
+ /etc/dovecot/local.conf in care sunt setari incluse pt:
		include 10-auth.conf
		include 10-mail.conf
		include 10-master.conf
		include 10-ssl.conf
		include 15-lda.conf
		include 20-imap.conf
		include 20-lmtp.conf
		include 20-managesieve.conf
		include 20-pop3.conf
		include 90-plugin.conf
		include 90-sieve.conf
+ /etc/dovecot/dovecot-sql.conf.ext
+ /etc/dovecot/dovecot-dict-quota.conf.ext
+ /etc/dovecot/conf.d/10-auth.conf 
 ...
 
 
^ test VDA patch
''postconf | grep virtual_maildir_''

... to do ...
plugin rouncube -vacation?
dovecot quota_warning
iptables or firewalld
selinux?
fail2ban?


