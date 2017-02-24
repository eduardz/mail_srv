# mail_srv
config-script
postfix_VDA+dovecot+mariadb(Quota)+amavisd(spamassasin+clam)

* Configure first LVM and mount LogicalVolume in home folder for postfix user

* Patch Postfix with VDA_patch, from here:
http://vda.sourceforge.net/

Run mail script 
1)
installed 
	- postfix_VDA manual-update 
	- postfixadmin (web -> update)
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
setat DKIM  
  -DMARC to add TXT DNS record
 
 3)
Apache 2.4 latest - settings
mod_security = apache protection: protect from sql injection
	-virtual_host = roundcube-$
			apache redirect *80 -> 443
			roundcubemail/installer = deny frm all (403 error)
	-virtual_host = postfixadmin-$ 
			apache redirect *80 -> 443
scripted SSL certificates = /etc/httpd/ssl/*
- support for lets encrypt

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
+ /etc/dovecot/dovecot-sql.conf.ext
+ /etc/dovecot/dovecot-dict-quota.conf.ext
+ /etc/dovecot/conf.d/10-auth.conf 
 + managesieve -> vacancy setup in rouncube
 
 


... to do ...

dovecot quota_warning
iptables or firewalld
selinux?



