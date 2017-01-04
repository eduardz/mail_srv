#!/bin/bash
echo "MAINTAINER Eduard Zaharia"
echo "email server 2017 postfix+dovecot+mysql_quota+amavis(sa+clam)

# Update program links
WEB_LATEST_POSTFIXADM='https://netix.dl.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-3.0/postfixadmin-3.0.tar.gz'

## <Variables> ###
USR_ID=5377
#
SQL_ROOT_PASS='change_root_SQL_pass'
POSTFIX_USER='vmail'
POSTFIX_PASS='change-pass'
POSTFIX_SQL_DB='mail-sql_somepass'
POSTFIX_MAIL_LOCATION=/var/vmail
#
ROUNDCUBE_USER='user-rd'
ROUNDCUBE_PASS='chenge_pass_rd'
ROUNDCUBE_DB='rd_db0_04'
#
HOSTNAME_WEB=mail.example.ro
VH_ROUNCUBE='roundcube.example.ro'
VH_POSTFIXADMIN='postfix.example.ro'
SRV_ALIAS='webmail.example.ro'
MAIL_ADMIN='dev@euroweb.ro'
#
## </Variables> ###

# add email user-no-login #
groupadd -g $USR_ID $POSTFIX_USER
useradd -g $USR_ID -u $USR_ID -d $POSTFIX_MAIL_LOCATION $POSTFIX_USER -s /sbin/nologin -c "virtual postfix user"
### install ##################################################

# 1_install_POSTFIX+VDA-patched # patch postfix-version+VDA_patch
yum remove -y postfix
yum localinstall -y /home/tmp/postfix*.rpm

# _install_preparation
yum install -y epel-release 
# 8 packages to install
yum install -y amavisd-new clamav-server-systemd clamav-update dovecot dovecot-mysql dovecot-pigeonhole httpd pypolicyd-spf
# 8 packages to install
yum install -y mariadb mariadb-server mod_ssl mod_security ntp php php-imap spamassassin 
# 9 packages to install
yum install -y php-gd php-intl php-ldap php-mbstring php-mcrypt php-mysql php-xml roundcubemail opendkim
# 1.4_install_PostfixAdmin"
curl -s $WEB_LATEST_POSTFIXADM | tar zxvf - -C /var/www/html/
mv /var/www/html/postfixadmin-*/ /var/www/html/postfixadmin
chown apache:apache -R /var/www/html/postfixadmin

##########################################################

# Configure @mail ########################################
# set timezone
sed -i "s/^;date.timezone =$/date.timezone = \"Europe\/Bucharest\"/" /etc/php.ini 

# 2_enable @Boot_Services"
systemctl enable postfix dovecot httpd mariadb amavisd clamd@amavisd spamassassin opendkim

# 3.1_conf_RoundCube ##
cp /etc/roundcubemail/config.inc.php.sample /etc/roundcubemail/config.inc.php
chown root:apache /etc/roundcubemail/config.inc.php
echo "\$rcmail_config['force_https'] = true;" >> /etc/roundcubemail/config.inc.php
echo "\$rcmail_config['preview_pane'] = true;" >> /etc/roundcubemail/config.inc.php
# plain password compatible with crypt field #
echo "\$rcmail_config['imap_auth_type'] = 'LOGIN';" >> /etc/roundcubemail/config.inc.php
sed -i "s|^\(\$config\['db_dsnw'\] =\).*$|\1 \'mysqli://${ROUNDCUBE_USER}:${ROUNDCUBE_PASS}@localhost/${ROUNDCUBE_DB}\';|" /etc/roundcubemail/config.inc.php

# 3.2_conf_PostfixAdmin  ##
sed -i "s|^\(\$CONF\['configured'\] =\).*$|\1 \ true\;|" /var/www/html/postfixadmin/config.inc.php
sed -i "s|^\(\$CONF\['database_user'\] =\).*$|\1 \'$POSTFIX_USER\';|" /var/www/html/postfixadmin/config.inc.php
sed -i "s|^\(\$CONF\['database_password'\] =\).*$|\1 \'$POSTFIX_PASS\';|" /var/www/html/postfixadmin/config.inc.php
sed -i "s|^\(\$CONF\['database_name'\] =\).*$|\1 \'$POSTFIX_SQL_DB\';|" /var/www/html/postfixadmin/config.inc.php
# conf_PostfixAdmin-mailbox_quota / default user quota=1024MB
sed -i "s|^\(\$CONF\['maxquota'\] =\).*$|\1 \'1024\';|" /var/www/html/postfixadmin/config.inc.php
sed -i "s|^\(\$CONF\['quota'\] =\).*$|\1 \'YES\';|" /var/www/html/postfixadmin/config.inc.php
# domain quota (default enabled)
#sed -i "s|^\(\$CONF\['domain_quota'\] =\).*$|\1 \'NO\';|" /var/www/html/postfixadmin/config.inc.php

# 4.1_create SSL-Certs ###
mkdir -p /etc/httpd/ssl/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/httpd/ssl/$HOSTNAME_WEB.key <<EOF -out /etc/httpd/ssl/$HOSTNAME_WEB.crt 
RO
Bucharest
Bucharest
$HOSTNAME_WEB
$HOSTNAME_WEB-IT
$HOSTNAME_WEB
$MAIL_ADMIN
EOF
#

# 4.1_conf_DKIM 
mkdir -p /etc/opendkim/keys/$HOSTNAME_WEB
/usr/sbin/opendkim-genkey -D /etc/opendkim/keys/$HOSTNAME_WEB/ -d $HOSTNAME_WEB -s dkim_selector
chown -R opendkim:opendkim /etc/opendkim/keys/*
echo "*@$HOSTNAME_WEB dkim_selector._domainkey.$HOSTNAME_WEB" >> /etc/opendkim/SigningTable
echo "*dkim_selector._domainkey.$HOSTNAME_WEB $HOSTNAME_WEB:dkim_selector:/etc/opendkim/keys/$HOSTNAME_WEB/dkim_selector" >> /etc/opendkim/KeyTable
echo "localhost" >> /etc/opendkim/TrustedHosts
cat <<EOT > /etc/opendkim.conf
## opendkim.conf -- configuration file for OpenDKIM filter
AutoRestart             Yes
AutoRestartRate         10/1h
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
LogWhy                  Yes
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
SigningTable            refile:/etc/opendkim/SigningTable
Socket                  inet:8891@localhost
Syslog                  Yes
SyslogSuccess           Yes
TemporaryDirectory      /var/tmp
UMask                   022
UserID                  opendkim:opendkim
EOT

# 4.2_config_HTTPD=(virtual-hosts)
rm -f /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/roundcubemail.conf

echo "Listen 443" >> /etc/httpd/conf/httpd.conf
cat <<EOT >> /etc/httpd/conf.d/vh1_postfix-roundcube.conf
<VirtualHost *:80>
    ServerName $VH_ROUNCUBE
    DocumentRoot /usr/share/roundcubemail
    Redirect / https://$VH_ROUNCUBE
</VirtualHost>
<VirtualHost *:443>
    ServerName $VH_ROUNCUBE
    ServerAlias $SRV_ALIAS
    ServerAlias $VH_ROUNCUBE
    ServerAdmin $MAIL_ADMIN
    DocumentRoot /usr/share/roundcubemail
    ErrorLog /var/log/httpd/error_log
# Apache Self Signed Certificate
    SSLEngine On
    SSLCertificateFile /etc/httpd/ssl/$HOSTNAME_WEB.crt
    SSLCertificateKeyFile /etc/httpd/ssl/$HOSTNAME_WEB.key
    SSLCipherSuite HIGH:!MEDIUM:!aNULL:!MD5:!RC4
<Directory /usr/share/roundcubemail/>
    Options -Indexes
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
</Directory>
<Directory /usr/share/roundcubemail/installer/>
        AllowOverride All
        Order allow,deny
        Deny from all
</Directory>
# Those directories should not be viewed by Web clients.
<Directory /usr/share/roundcubemail/bin/>
    Order Allow,Deny
    Deny from all
</Directory>
<Directory /usr/share/roundcubemail/plugins/enigma/home/>
    Order Allow,Deny
    Deny from all
</Directory>
# Secure
    ErrorDocument 404 /
    Options -FollowSymLinks
    Header always append X-Frame-Options SAMEORIGIN
    Header set X-XSS-Protection "1; mode=block"
</VirtualHost>
EOT

#
cat <<EOT >> /etc/httpd/conf.d/vh2_postfix-postfixadmin.conf
<VirtualHost *:80>
    ServerName $VH_POSTFIXADMIN
    DocumentRoot /var/www/html/postfixadmin
    Redirect / https://$VH_POSTFIXADMIN
</VirtualHost>
<VirtualHost *:443>
    ServerName $VH_POSTFIXADMIN
    ServerAdmin dev@euroweb.ro
    DocumentRoot /var/www/html/postfixadmin
    ErrorLog /var/log/httpd/error_log
# Apache Self Signed Certificate
    SSLEngine On
    SSLCertificateFile /etc/httpd/ssl/$HOSTNAME_WEB.crt
    SSLCertificateKeyFile /etc/httpd/ssl/$HOSTNAME_WEB.key
    SSLCipherSuite HIGH:!MEDIUM:!aNULL:!MD5:!RC4
<Directory /var/www/html/postfixadmin/>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
#  setup.php = not secured
#    <Files setup.php>
#        Require all denied
#    </Files>
</Directory>
    Options -FollowSymLinks
    Header set X-XSS-Protection "1; mode=block"
# Apache user/pass protection for postfixadmin
#    <Location />
#        Order allow,deny
#        Allow from all
#        AuthType Basic
#        AuthName "Restricted Files"
#        AuthBasicProvider file
#        AuthUserFile /etc/httpd/conf/.htpasswd
#        Require user euroweb
#    </Location>
</VirtualHost>
EOT
#

#################################################
# 5_conf_PostFix/Dovecot - files
cat <<EOT >> /etc/postfix/mysql_virtual_alias_maps.cf
user = $POSTFIX_USER
password = $POSTFIX_PASS
hosts = localhost
dbname = $POSTFIX_SQL_DB
table = alias
select_field = goto
where_field = address
EOT
#
cat <<EOT >> /etc/postfix/mysql_virtual_domains_maps.cf
user = $POSTFIX_USER
password = $POSTFIX_PASS
hosts = localhost
dbname = $POSTFIX_SQL_DB
table = domain
select_field = domain
where_field = domain
additional_conditions = and active = '1'
EOT
#
cat <<EOT >> /etc/postfix/mysql_virtual_mailbox_maps.cf
user = $POSTFIX_USER
password = $POSTFIX_PASS
hosts = localhost
dbname = $POSTFIX_SQL_DB
table = mailbox
select_field = maildir
where_field = username
EOT
#
cat <<EOT >> /etc/postfix/mysql_virtual_mailbox_limit_maps.cf
user = $POSTFIX_USER
password = $POSTFIX_PASS
hosts = localhost
dbname = $POSTFIX_SQL_DB
query = SELECT quota FROM mailbox WHERE username='%s' AND active = '1'
EOT
#
cat <<EOT >> /etc/dovecot/dovecot-sql.conf.ext
driver = mysql
connect = host=localhost dbname=$POSTFIX_SQL_DB user=$POSTFIX_USER password=$POSTFIX_PASS
default_pass_scheme = MD5-CRYPT

password_query = SELECT password FROM mailbox WHERE username = '%u' AND active = '1'

user_query = SELECT concat('$POSTFIX_MAIL_LOCATION/domains/', maildir) AS home, \
  $USR_ID AS uid, $USR_ID AS gid, \
  CONCAT('*:bytes=', mailbox.quota) AS quota2_rule, \
  CONCAT('*:bytes=', domain.quota*1024000) AS quota_rule \
  FROM mailbox,domain WHERE username = '%u' AND mailbox.active = '1' \
  AND domain.domain = '%d'
iterate_query = SELECT username FROM mailbox
EOT
#
cat <<EOT >> /etc/dovecot/dovecot-dict-quota.conf.ext
connect = host=localhost dbname=$POSTFIX_SQL_DB user=$POSTFIX_USER password=$POSTFIX_PASS
map {
  pattern = priv/quota/storage
  table = quota2
  username_field = username
  value_field = bytes
}
map {
  pattern = priv/quota/messages
  table = quota2
  username_field = username
  value_field = messages
}
EOT
#
cat <<EOT > /etc/dovecot/conf.d/10-auth.conf
!include auth-sql.conf.ext
EOT
### PostFix_MAIN.CF #####################################
cat <<EOT > /etc/postfix/main.cf
myhostname = $HOSTNAME_WEB
mydomain = $HOSTNAME_WEB
myorigin = \$myhostname

inet_interfaces = all
inet_protocols = ipv4
mydestination = \$myhostname, localhost
mynetworks = 127.0.0.0/8
home_mailbox = Maildir/

smtpd_banner = \$myhostname ESMTP Unknown
disable_vrfy_command = yes

#smtpd_client_restrictions =
#    check_client_access hash:/etc/postfix/access
#    reject_rbl_client zen.spamhaus.org
#    reject_rbl_client bl.spamcop.net
#    reject_rbl_client all.rbl.jp
#    reject_non_fqdn_sender
#    reject_unknown_sender_domain
#    reject_invalid_hostname

smtpd_sender_restrictions =
        reject_rhsbl_sender zen.spamhaus.org
        reject_unknown_sender_domain
# Dovecot SASL
smtpd_sasl_auth_enable = yes
smtpd_sasl_local_domain = \$myhostname
smtpd_sasl_security_options = noanonymous

smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
broken_sasl_auth_clients = yes
smtpd_tls_security_level = encrypt

smtpd_recipient_restrictions =
    permit_mynetworks
    permit_sasl_authenticated
    reject_unauth_destination
    check_policy_service unix:private/policy-spf

## CERTS
#smtpd_tls_CAfile = /etc/httpd/ssl/$HOSTNAME_WEB.pem######
smtpd_tls_cert_file = /etc/httpd/ssl/$HOSTNAME_WEB.crt
smtpd_tls_key_file = /etc/httpd/ssl/$HOSTNAME_WEB.key
#smtp_tls_CAfile = /etc/httpd/ssl/$HOSTNAME_WEB.pem

smtp_tls_security_level = encrypt
smtp_tls_loglevel = 1
smtp_tls_protocols = !SSLv2, !SSLv3
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3

smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:/var/lib/postfix/smtpd_scache
smtpd_tls_session_cache_timeout = 3600s

# DKIM support for postfix
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = \$smtpd_milters
milter_default_action = accept

# Virtual Domain MySQL
local_transport = local
#virtual_transport = virtual
virtual_transport = dovecot
dovecot_destination_recipient_limit = 1
virtual_mailbox_base = $POSTFIX_MAIL_LOCATION
virtual_alias_maps = mysql:/etc/postfix/mysql_virtual_alias_maps.cf
virtual_alias_domains = \$virtual_alias_maps
virtual_mailbox_domains = mysql:/etc/postfix/mysql_virtual_domains_maps.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql_virtual_mailbox_maps.cf
virtual_uid_maps = static:$USR_ID
virtual_gid_maps = static:$USR_ID
virtual_minimum_uid = $USR_ID

# Quota postfix_VDA Patch
virtual_maildir_extended = yes
virtual_mailbox_limit_maps = mysql:/etc/postfix/mysql_virtual_mailbox_limit_maps.cf
virtual_mailbox_limit_override = yes
virtual_overquota_bounce = no
virtual_trash_count = no

# Amavisd-New
content_filter=smtp-amavis:[127.0.0.1]:10024
receive_override_options = no_address_mappings
EOT
#
cat <<EOT > /etc/postfix/master.cf
smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject

smtps     inet  n       -       n       -       -       smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o receive_override_options=no_address_mappings

smtp-amavis unix  -      -       n       -       2       smtp
     -o smtp_data_done_timeout=1200
     -o smtp_send_xforward_command=yes
     -o disable_dns_lookups=yes

127.0.0.1:10025 inet n   -       n       -       -       smtpd
     -o content_filter=
     -o local_recipient_maps=
     -o relay_recipient_maps=
     -o smtpd_restriction_classes=
     -o smtpd_client_restrictions=
     -o smtpd_helo_restrictions=
     -o smtpd_sender_restrictions=
     -o smtpd_recipient_restrictions=permit_mynetworks,reject
     -o mynetworks=127.0.0.0/8
     -o mynetworks_style=host
     -o strict_rfc821_envelopes=yes
     -o smtpd_error_sleep_time=0
     -o smtpd_soft_error_limit=1001
     -o smtpd_hard_error_limit=1000
     -o receive_override_options=no_address_mappings
     -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks


dovecot  unix    -       n       n       -       -       pipe
     flags=DRhu user=$POSTFIX_USER:$POSTFIX_USER argv=/usr/libexec/dovecot/deliver -f \${sender} -d \${recipient}
#postfix-newer vers#      flags=DRhu user=$POSTFIX_USER:$POSTFIX_USER argv=/usr/libexec/dovecot/deliver -f \${sender} -d \${user}@\${nexthop}

# Prevent sender address forgery with Sender Policy Framework(SPF); postfix checks SPF record on all incoming email#
policy-spf unix -       n       n       -       0       spawn
     user=nobody argv=/usr/bin/python /usr/libexec/postfix/policyd-spf /etc/python-policyd-spf/policyd-spf.conf

pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
#qmgr     fifo  n       -       -       300     1       oqmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
smtp      unix  -       -       n       -       -       smtp
        -o smtp_bind_address=192.168.2.89 
        #change_this_to email-IP
#proxywrite unix -       -       n       -       1       proxymap
EOT

# conf_Dovecot#################
cat <<EOT >> /etc/dovecot/local.conf
## dovecot.conf
protocols = imap pop3 sieve
listen = *

## 10-auth.conf
disable_plaintext_auth = yes
auth_mechanisms = plain login cram-md5
#!include auth-system.conf.ext
#!include dovecot-sql.conf.ext

passdb {
  driver = pam
}
userdb {
  driver = passwd
}
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

## 10-mail.conf
mail_location = maildir:$POSTFIX_MAIL_LOCATION/%d/%n
first_valid_uid = $USR_ID
first_valid_gid = $USR_ID

namespace inbox {
  separator = .
  prefix =
  location = maildir:$POSTFIX_MAIL_LOCATION/%d/%n/maildir
  inbox = yes

  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }
  mailbox virtual/All {
    auto = no
    special_use = \All
  }
}

## 10-master.conf
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  # Sive Setting
    unix_listener auth-client {
        group = postfix
        mode = 0660
        user = postfix
    }
    unix_listener auth-master {
        group = $POSTFIX_USER
        mode = 0660
        user = $POSTFIX_USER
    }
    user = root
  # Sive Setting
}
service dict {
  unix_listener dict {
    mode = 0660
    user = $POSTFIX_USER
    group = $POSTFIX_USER
  }
}

## 10-ssl.conf
ssl_cert = </etc/httpd/ssl/$HOSTNAME_WEB.crt
ssl_key = </etc/httpd/ssl/$HOSTNAME_WEB.key
ssl_ca = </etc/httpd/ssl/$HOSTNAME_WEB.key
ssl_verify_client_cert = yes
ssl_protocols = !SSLv2 !SSLv3

##15-lda.conf
protocol lda {
  mail_plugins = \$mail_plugins sieve quota
  postmaster_address = postmaster@localhost
  hostname = $HOSTNAME_WEB
  auth_socket_path = /var/run/dovecot/auth-master
  log_path = $POSTFIX_MAIL_LOCATION/dovecot-lda-errors.log
  info_log_path = $POSTFIX_MAIL_LOCATION/dovecot-lda.log
}

## 20-imap.conf
protocol imap {
  imap_client_workarounds = delay-newmail tb-extra-mailbox-sep
  mail_plugins = \$mail_plugins quota virtual imap_quota
}

## 20-lmtp.conf
protocol lmtp {
  mail_plugins = \$mail_plugins sieve quota
  log_path = $POSTFIX_MAIL_LOCATION/dovecot-lmtp-errors.log
  info_log_path = $POSTFIX_MAIL_LOCATION/dovecot-lmtp.log
}

## 20-managesieve.conf
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}
service managesieve {
}
protocol sieve {
  managesieve_max_line_length = 65536
  managesieve_implementation_string = dovecot
  log_path = $POSTFIX_MAIL_LOCATION/dovecot-sieve-errors.log
  info_log_path = $POSTFIX_MAIL_LOCATION/dovecot-sieve.log
}

## 20-pop3.conf
protocol pop3 {
  mail_plugins = quota
  pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
}

## 90-plugin.conf
dict {
    quota = mysql:/etc/dovecot/dovecot-dict-quota.conf.ext
}
plugin {
    quota2 = dict:User quota::proxy::quota
    quota = dict:Domain quota:%d:proxy::quota
}

## 90-sieve.conf
plugin {
  #sieve = ~/.dovecot.sieve
  sieve = $POSTFIX_MAIL_LOCATION/%d/%n/.dovecot.sieve
  #sieve_dir = ~/sieve
  sieve_dir = $POSTFIX_MAIL_LOCATION/%d/%n/sieve
  sieve_global_dir = /etc/dovecot/sieve/global/
  sieve_global_path = /etc/dovecot/sieve/default.sieve
}
EOT

# 6_conf_AMAVISD-New ##
sed -i "s|^\(\$mydomain\ =\).*$|\1 \'localhost\';|" /etc/amavisd/amavisd.conf
cat <<EOT >> /etc/amavisd/amavisd.conf
 @lookup_sql_dsn = (
     ['DBI:mysql:database=$POSTFIX_SQL_DB;host=127.0.0.1;port=3306', '$POSTFIX_USER', '$POSTFIX_PASS'],
 );
 \$sql_select_white_black_list = undef;

 \$sql_select_policy = 'SELECT "Y" as local, 1 as id FROM domain WHERE
     CONCAT("@",domain) IN (%k)';

\$recipient_delimiter = undef;
EOT
#
## 7_config_CLAM@amavis ##
sed -i -e 's/^Example/#Example/' /etc/freshclam.conf
echo > /etc/sysconfig/freshclam

# echo "start @mail services"
systemctl start postfix dovecot httpd mariadb amavisd clamd@amavisd spamassassin opendkim

### _Config MySQL_secure_install#
# ENTER 2 setup password#
mysql_secure_installation <<EOF

y
$SQL_ROOT_PASS
$SQL_ROOT_PASS
y
y
y
y
EOF
#

# 8_conf SQL_DB: postfix-db / rouncube-db
mysql -uroot -p$SQL_ROOT_PASS -e "CREATE DATABASE $POSTFIX_SQL_DB CHARACTER SET utf8 COLLATE utf8_general_ci;" 
mysql -uroot -p$SQL_ROOT_PASS -e "CREATE DATABASE $ROUNDCUBE_DB CHARACTER SET utf8 COLLATE utf8_general_ci;"
#
mysql -uroot -p$SQL_ROOT_PASS -e "CREATE USER $POSTFIX_USER@localhost IDENTIFIED BY '$POSTFIX_PASS';"
mysql -uroot -p$SQL_ROOT_PASS -e "CREATE USER $ROUNDCUBE_USER@localhost IDENTIFIED BY '$ROUNDCUBE_PASS';"
#
mysql -uroot -p$SQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON $POSTFIX_SQL_DB.* TO '$POSTFIX_USER'@'localhost';"
mysql -uroot -p$SQL_ROOT_PASS -e "GRANT ALL PRIVILEGES ON $ROUNDCUBE_DB.* TO '$ROUNDCUBE_USER'@'localhost';"
mysql -uroot -p$SQL_ROOT_PASS -e "FLUSH PRIVILEGES;"
#
#initialize RoundCube-DB
mysql -u root -p$SQL_ROOT_PASS $ROUNDCUBE_DB < /usr/share/roundcubemail/SQL/mysql.initial.sql
#
echo "
os=CentOS7
installed Postfix_VDA+Dovecot+Amavisd(spamaassassin+clam)+MariaDB(MySQL)+Apache2.4+OpenDKIM+Apache-mod_security+policy-SPF+PostfixAdmin
sleep 3
##
to do
- configure passwd postfixadmin in config + create admin user
- secure postfixadmin
- setup iptables; cronjobs (sa-update; clam update; sql-dump)
- conf DMARK
- "

