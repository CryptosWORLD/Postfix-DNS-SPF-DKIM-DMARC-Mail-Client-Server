nameserver_address='192.168.188.10'

sudo apt update
sudo hostnamectl set-hostname srv-smtp-01.mail02.web
sudo apt install postfix -y
sudo apt install telnet -y
sudo apt install dovecot-lmtpd -y

sudo postconf mail_spool_directory

sudo systemctl restart postfix
sudo apt install mailutils -y

cat << 'EOF' > create-cert.sh
#!/bin/bash
openssl genrsa -des3 -out mail.mail02.web.key 2048
chmod 600 mail.mail02.web.key
openssl req -new -key mail.mail02.web.key -out mail.mail02.web.csr -subj "/C=CH/ST=VD/L=SteCroix/O=LoucSA/CN=mail.mail02.web"

openssl x509 -req -days 365 -in mail.mail02.web.csr -signkey mail.mail02.web.key -out mail.mail02.web.crt

openssl rsa -in mail.mail02.web.key -out mail.mail02.web.key.nopass
mv mail.mail02.web.key.nopass mail.mail02.web.key
openssl req -new -x509 -extensions v3_ca -keyout cakey.pem -out cacert.pem -subj "/C=CH/ST=VD/L=SteCroix/O=LoucSA/CN=root-ca.LoucSA.local" -days 3650 


chmod 600 mail.mail02.web.key
chmod 600 cakey.pem
mv mail.mail02.web.key /etc/ssl/private/
mv mail.mail02.web.crt /etc/ssl/certs/
mv cakey.pem /etc/ssl/private/
mv cacert.pem /etc/ssl/certs/
postconf -e 'smtpd_tls_auth_only = no'
postconf -e 'smtp_use_tls = yes'
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtp_tls_note_starttls_offer = yes'
postconf -e 'smtpd_tls_key_file = /etc/ssl/private/mail.mail02.web.key'
postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/mail.mail02.web.crt'
postconf -e 'smtpd_tls_CAfile = /etc/ssl/certs/cacert.pem'
postconf -e 'smtpd_tls_loglevel = 1'
postconf -e 'smtpd_tls_received_header = yes'
postconf -e 'smtpd_tls_session_cache_timeout = 3600s'
postconf -e 'tls_random_source = dev:/dev/urandom'
postconf -e 'myhostname = mail.mail02.web'
EOF

sudo chmod +x create-cert.sh
sudo ./create-cert.sh

sudo apt install dovecot-core dovecot-imapd -y
sudo postconf mail_spool_directory
sudo adduser dovecot mail

cat << 'EOF' > /etc/dovecot/dovecot.conf
## Dovecot configuration file

protocols = imap lmtp

!include_try /usr/share/dovecot/protocols.d/*.protocol

dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
}

!include conf.d/*.conf

!include_try local.conf
EOF



cat << 'EOF' > /etc/dovecot/conf.d/10-auth.conf

disable_plaintext_auth = yes
auth_username_format = %n
auth_mechanisms = plain login
!include auth-system.conf.ext
EOF


cat << 'EOF' > /etc/dovecot/conf.d/10-master.conf

service imap-login {
  inet_listener imap {
    #port = 143
  }
  inet_listener imaps {
    #port = 993
    #ssl = yes
  }

}

service pop3-login {
  inet_listener pop3 {
    #port = 110
  }
  inet_listener pop3s {
    #port = 995
    #ssl = yes
  }
}

service submission-login {
  inet_listener submission {
    #port = 587
  }
}

service lmtp {
 unix_listener /var/spool/postfix/private/dovecot-lmtp {
   mode = 0600
   user = postfix
   group = postfix
  }
}
service imap {
  # Most of the memory goes to mmap()ing files. You may need to increase this
  # limit if you have huge mailboxes.
  #vsz_limit = $default_vsz_limit

  # Max. number of IMAP processes (connections)
  #process_limit = 1024
}

service pop3 {
  # Max. number of POP3 processes (connections)
  #process_limit = 1024
}

service submission {
  # Max. number of SMTP Submission processes (connections)
  #process_limit = 1024
}

service auth {
    unix_listener /var/spool/postfix/private/auth {
      mode = 0660
      user = postfix
      group = postfix
    }
}

service auth-worker {
  # Auth worker process is run as root by default, so that it can access
  # /etc/shadow. If this isn't necessary, the user should be changed to
  # $default_internal_user.
  #user = root
}

service dict {
  # If dict proxy is used, mail processes should have access to its socket.
  # For example: mode=0660, group=vmail and global mail_access_groups=vmail
  unix_listener dict {
    #mode = 0600
    #user =
    #group =
  }
}

EOF


sudo systemctl restart postfix dovecot
sudo ss -lnpt | grep dovecot

cat << 'EOF' > /etc/dovecot/conf.d/10-mail.conf
##
## Mailbox locations and namespaces
##

mail_location = maildir:~/Maildir
namespace inbox {
  inbox = yes
}
mail_privileged_group = mail

protocol !indexer-worker {
  # If folder vsize calculation requires opening more than this many mails from
  # disk (i.e. mail sizes aren't in cache already), return failure and finish
  # the calculation via indexer process. Disabled by default. This setting must
  # be 0 for indexer-worker processes.
  #mail_vsize_bg_after_count = 0
}
EOF


cat << 'EOF' > /etc/dovecot/conf.d/10-ssl.conf
# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = required

ssl_cert = </etc/ssl/certs/mail.mail02.web.crt
ssl_key = </etc/ssl/private/mail.mail02.web.key

ssl_client_ca_dir = /etc/ssl/certs

ssl_dh = </usr/share/dovecot/dh.pem

ssl_min_protocol = TLSv1.2

# Prefer the server's order of ciphers over client's.
ssl_prefer_server_ciphers = yes
EOF

sudo apt install postfix-policyd-spf-python -y

cat << 'EOF' > /etc/postfix/master.cf
#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd

#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd

maildrop  unix  -       n       n       -       -       pipe
  flags=DRXhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
#
# Other external delivery methods.
#
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FRX user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py ${nexthop} ${user}

submission     inet     n    -    y    -    -    smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_wrappermode=no
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth

policyd-spf  unix  -       n       n       -       0       spawn
    user=policyd-spf argv=/usr/bin/policyd-spf

EOF


sudo systemctl restart postfix
sudo systemctl restart dovecot
sudo apt install opendkim opendkim-tools -y
sudo gpasswd -a postfix opendkim

sudo mkdir -p /etc/opendkim/keys
sudo chown -R opendkim:opendkim /etc/opendkim
sudo chmod go-rw /etc/opendkim/keys

cat << 'EOF' > /etc/opendkim/signing.table
*@mail02.web      default._domainkey.mail02.web
*@*.mail02.web    default._domainkey.mail02.web
EOF

cat << 'EOF' > /etc/opendkim/key.table
default._domainkey.mail02.web     mail02.web:default:/etc/opendkim/keys/mail02.web/default.private
EOF

cat << 'EOF' > /etc/opendkim/trusted.hosts
127.0.0.1
localhost

.mail02.web
EOF

sudo mkdir /etc/opendkim/keys/mail02.web
sudo opendkim-genkey -b 2048 -d mail02.web -D /etc/opendkim/keys/mail02.web -s default -v
sudo chown opendkim:opendkim /etc/opendkim/keys/mail02.web/default.private
sudo chmod 600 /etc/opendkim/keys/mail02.web/default.private
sudo cat /etc/opendkim/keys/mail02.web/default.txt

sudo mkdir /var/spool/postfix/opendkim
sudo chown opendkim:postfix /var/spool/postfix/opendkim

cat <<EOF > /etc/opendkim.conf
Syslog                  yes
SyslogSuccess           yes

Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
OversignHeaders         From

UserID                  opendkim
UMask                   007

Socket                  local:/var/spool/postfix/opendkim/opendkim.sock

PidFile                 /run/opendkim/opendkim.pid

Nameservers             $nameserver_address

# Map domains in From addresses to keys used to sign messages
KeyTable           refile:/etc/opendkim/key.table
SigningTable       refile:/etc/opendkim/signing.table

# Hosts to ignore when verifying signatures
ExternalIgnoreList  /etc/opendkim/trusted.hosts

# A set of internal hosts whose mail should be signed
InternalHosts       /etc/opendkim/trusted.hosts
EOF

cat << 'EOF' > /etc/default/opendkim

#RUNDIR=/var/spool/postfix/run/opendkim
RUNDIR=/run/opendkim

#SOCKET=local:$RUNDIR/opendkim.sock
SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock"

# listen on all interfaces on port 54321:
#SOCKET=inet:54321
# listen on loopback on port 12345:
#SOCKET=inet:12345@localhost
# listen on 192.0.2.1 on port 12345:
#SOCKET=inet:12345@192.0.2.1
USER=opendkim
GROUP=opendkim
PIDFILE=$RUNDIR/$NAME.pid
EXTRAAFTER=
EOF


cat << 'EOF' > /etc/postfix/main.cf
# See /usr/share/postfix/main.cf.dist for a commented, more complete version

#Enable TLS Encryption when Postfix receives incoming emails
smtpd_tls_cert_file=/etc/ssl/certs/mail.mail02.web.crt
smtpd_tls_key_file=/etc/ssl/private/mail.mail02.web.key
smtpd_tls_security_level=may
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache

#Enable TLS Encryption when Postfix sends outgoing emails
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

#Enforce TLSv1.3 or TLSv1.2
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 3.6 on
# fresh installs.
compatibility_level = 3.6



# TLS parameters
smtpd_tls_cert_file = /etc/ssl/certs/mail.mail02.web.crt
smtpd_tls_key_file = /etc/ssl/private/mail.mail02.web.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache


smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = mail.mail02.web
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $myhostname, mail02.web, srv-smtp-01.mail02.web, localhost.mail02.web, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

maillog_file = /var/log/postfix.log

smtpd_tls_auth_only = no
smtp_use_tls = yes
smtpd_use_tls = yes
smtp_tls_note_starttls_offer = yes
smtpd_tls_CAfile = /etc/ssl/certs/cacert.pem
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
tls_random_source = dev:/dev/urandom

mailbox_transport = lmtp:unix:private/dovecot-lmtp
smtputf8_enable = no

policyd-spf_time_limit = 3600
smtpd_recipient_restrictions =
   permit_mynetworks,
   permit_sasl_authenticated,
   reject_unauth_destination,
   check_policy_service unix:private/policyd-spf

# Milter configuration
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:opendkim/opendkim.sock
non_smtpd_milters = $smtpd_milters
EOF

sudo systemctl restart opendkim postfix

printf 'Copy public key to your DNS and press [enter] to continue...'
read _

sudo opendkim-testkey -d mail02.web -s default -vvv
#sudo apt install opendmarc -y
#sudo opendmarc-check mail02.web
