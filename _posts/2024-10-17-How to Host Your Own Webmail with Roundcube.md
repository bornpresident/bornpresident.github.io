---
title: How to Host Your Own Webmail with Roundcube
author: Vishal Chand
date: 2024-10-17
categories: [Security Operation Centre]
tags: [Email, Rouncube]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/2.png
---

- **Postfix:** An open-source mail transfer agent (MTA) that handles sending and receiving emails using SMTP.

- **Dovecot:** An open-source IMAP and POP3 server that manages email retrieval and storage, allowing users to access their emails securely.

- **Roundcube:** A web-based email client that provides a user-friendly interface for managing emails via a browser.
### Perquisites 
Domain name pointed to your VPS IP address. 

### Step 1 : Set up the Hostname 

```shell
hostnamectl set-hostname <hostname> 
```

* Open /etc/hosts file and bind your server IP address with the hostname:

```shell
nano /etc/hosts
```

* Add the following line:

```shell
your-server-ip   <hostname>
```
* Save and close the file. Then, run the following command to apply the configuration changes:

```shell
hostname -f
```

### Step 2 : Install Apache, MariaDB & PHP

* Roundcube requires Apache, MariaDB and PHP to be installed on your server. You can install them with the following command:

```shell
apt-get install apache2 mariadb-server php libapache2-mod-php php-mysql -y
```

*  After installing all the required packages, you will need to enable the Apache rewrite module for Roundcube to work. You can enable it with the following command:

```shell
a2enmod rewrite
```

* Next, reload the Apache service to apply the changes:

```shell
systemctl restart apache2
```

### Step 3 : Install Let's Encrypt SSL Certificate 

* Install the Let’s Encrypt Free SSL certificate on your server to configure your mail server with TLS.
* First, install the Certbot client in your server with the following command:

```shell
add-apt-repository ppa:certbot/certbot
apt-get update -y
apt-get install python-certbot-apache -y
```

* Now download the Let’s Encrypt Free SSL certificate for your domain email.example.com with the following command:

```shell
certbot certonly --apache -d <hostname>
```

### Step 4 : Install and Configure Postfix

```shell
apt-get install postfix
```

* You will be redirected to the screen. Select `Internet Site` for General type of mail configuration. Povide your domain name and hit **Tab** and **Enter** to finish the installation.
* The default Postfix configuration file is located at /etc/postfix/main.cf. Before configuring Postfix, it is recommended to back up this file:

```shell
mv /etc/postfix/main.cf /etc/postfix/main.cf.bak
```

* Create a new Postfix configuration file as shown below:
```shell
nano /etc/postfix/main.cf
```

* Add the following lines:
```bash
# GENERAL SETTINGS
smtpd_banner = $myhostname ESMTP $mail_name
biff = no
append_dot_mydomain = no
readme_directory = no
# SMTP SETTINGS
smtp_use_tls=yes
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
# SMTPD SETTINGS
smtpd_use_tls=yes
smtpd_tls_security_level = may
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtpd_tls_cert_file=/etc/letsencrypt/live/email.example.com/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/email.example.com/privkey.pem
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated,  reject_unauth_destination
# SASL SETTINGS
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
# VIRTUAL MAIL BOX AND LMTP SETTINGS
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = /etc/postfix/virtual_mailbox_domains
# OTHER SETTINGS
myhostname = email.example.com
myorigin = /etc/mailname
mydestination =  localhost.$mydomain, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
```

* Save and close the file.
* Define your domain in the /etc/postfix/virtual_mailbox_domains file:
```shell
nano /etc/postfix/virtual_mailbox_domains
```

* Add the following line:
```bash
soc.test.lab.ac.in #domain
```

* Save and close the file then convert the file to a format that Postfix can understand with the following command:
```bash
postmap /etc/postfix/virtual_mailbox_domains
```
* Edit the Postfix master configuration file:

```shell
nano /etc/postfix/master.cf
```

* Uncomment the following line : 
```shell
submission inet n       -       y       -       -       smtpd
```
* Save and close the file when you are finished.
### Step 5 : Install and Configure Dovecot

* Install Dovecot with other required packages
```
apt-get install dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd -y
```

* Define the Dovecot mail location to communicate with Postfix and virtual mailbox domains.

```shell
nano /etc/dovecot/conf.d/10-mail.conf
```

* Find the following line:

```shell
mail_location = mbox:~/mail:INBOX=/var/mail/%u
```

Replace it with 
```shell
mail_location = maildir:/var/mail/vhosts/%d/%n
```

Save and close the file.

* Create the Dovecot vhosts directory and the sub-directory for your domain name.

```shell
mkdir /var/mail/vhosts
mkdir /var/mail/vhosts/example.com
```

* Create a mail user and a group, and assign the ownership of the directories to the vmail user.

```shell
groupadd -g 5000 vmail
useradd -r -g vmail -u 5000 vmail -d /var/mail/vhosts -c "virtual mail user"
chown -R vmail:vmail /var/mail/vhosts/
```

* Edit the Dovecot master configuration file and enable IMAP and POP3 secure services:

```shell 
nano /etc/dovecot/conf.d/10-master.conf
```

* Find the following lines:
```shell
inet_listener imaps {
    #port = 993
    #ssl = yes
  }
```

And replace them with the following:

```shell
inet_listener imaps {
    port = 993
    ssl = yes
  }
```

On the same file, find the following lines:

```shell
inet_listener pop3s {
    #port = 995
    #ssl = yes
  }
```

And replace them with the following:

```shell 
inet_listener pop3s {
    port = 995
    ssl = yes
  }
```

Next, find the following lines:

```shell
service lmtp {
unix_listener lmtp {
#mode = 0666
}
```

And replace them with the following:
```shell
service lmtp {
unix_listener /var/spool/postfix/private/dovecot-lmtp {
mode = 0600
user = postfix
group = postfix
}
```

Next, find the following lines:

```shell
service  auth {
  # Postfix smtp-auth
  #unix_listener /var/spool/postfix/private/auth {
  #  mode = 0666
  #}
}
```

And replace them with the following:

```shell
service auth {
...
#Postfix smtp-auth
unix_listener /var/spool/postfix/private/auth {
mode = 0666
user=postfix
group=postfix
}
```

Save and close the file when you are finished.

* Set up the Dovecot authentication process

```shell
nano /etc/dovecot/conf.d/10-auth.conf
```

Uncomment the following line:

```shell
disable_plaintext_auth = yes
```

On the same file, find the following line:

```shell
auth_mechanisms = plain
```

And replace it with the following:

```shell
auth_mechanisms = plain login
```

* Comment out the following line to disable the default Dovecot behaviour for authenticating users.

```shell
#!include auth-system.conf.ext
```

Next, uncomment the following line to enable password file configuration.

```shell
!include auth-passwdfile.conf.ext
```

Save and close the file/

Next, edit the /etc/dovecot/conf.d/auth-passwdfile.conf.ext  file:

```shell
nano /etc/dovecot/conf.d/auth-passwdfile.conf.ext
```
Change the file as shown below:

```shell
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/dovecot-users
}
userdb {
driver = static
args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
```

Save and close the file.

* Create a password file for the user you want to assign an email account:

```shell
nano /etc/dovecot/dovecot-users
```

Add the following lines:

```shell
admin@example.com:admin@123
```

Save and close 

### Step 6 :Configure Dovecot to Use Let’s Encrypt SSL

* Configure Dovecot to work with SSL. You can do it by editing the file /etc/dovecot/conf.d/10-ssl.conf:

```shell
nano /etc/dovecot/conf.d/10-ssl.conf
```

Find the following line:

```shell
ssl = yes
```

Replace it with the following:

```shell
ssl = required
```

Next, find the following lines:

```shell
#ssl_cert = </etc/dovecot/dovecot.pem
#ssl_key = </etc/dovecot/private/dovecot.pem
```

And replace them with the following:

```shell
ssl_cert = </etc/letsencrypt/live/email.example.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/email.example.com/privkey.pem
```

Save and close the file when you are finished, then restart the Postfix and Dovecot services to apply the configuration changes:

```shell
systemctl restart postfix
systemctl restart dovecot
```

### Step 7 : Install and Configure Roundcube

```shell
apt-get install roundcube
```

During the installation, you will be prompted to configure the database. Choose your desired option and hit **Enter** to finish the installation.

* Configure the Apache virtual host for Roundcube. You can do it by editing the file /etc/apache2/sites-enabled/000-default.conf:

```shell
nano /etc/apache2/sites-enabled/000-default.conf
```

Change the file as shown below:

```shell
<VirtualHost *:80>
        Alias /mail /usr/share/roundcube

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```


Save and close the file, then restart the Apache web service to apply the changes:

```shell
systemctl restart apache2
```

Access your Roundcube Webmail 

```shell
http://email.VISHALCHAND.com/mail.
```

