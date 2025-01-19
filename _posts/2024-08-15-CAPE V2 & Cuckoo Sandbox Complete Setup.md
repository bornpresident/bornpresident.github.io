---
title: CAPE V2 & Cuckoo Sandbox Complete Setup
author: Vishal Chand
date: 2024-08-15
categories: [Malware Analysis]
tags: [CAPEv2,Cuckoo,Sandbox]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/7.png
---
# Complete Sandboxing Environment: Cuckoo and CAPE Installation Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Base System Setup](#base-system-setup)
4. [Cuckoo Installation](#cuckoo-installation)
5. [CAPE Installation](#cape-installation)
6. [Configuration](#configuration)
7. [Virtual Machine Setup](#virtual-machine-setup)
8. [Network Configuration](#network-configuration)
9. [Troubleshooting](#troubleshooting)

## Introduction

This guide covers the installation and configuration of both Cuckoo and CAPE Sandbox systems. While Cuckoo is the original system using Python 2.7, CAPE is its modern successor using Python 3. Having both systems can be beneficial for different analysis scenarios.

## Prerequisites

### System Requirements
- Ubuntu system (16.04 LTS for Cuckoo, Latest LTS for CAPE)
- Minimum 8GB RAM
- 50GB+ disk space
- CPU with virtualization support
- Internet connection
- Administrative privileges

### Required Software Base
```bash
# Update system
sudo apt-get update
sudo apt-get upgrade

# Basic dependencies
sudo apt-get install vim
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get install python-virtualenv python-setuptools
sudo apt-get install libjpeg-dev zlib1g-dev swig
sudo apt-get install python3-pip python3-dev
```

## Base System Setup

### 1. User Setup
```bash
# Create cuckoo user
sudo adduser cuckoo
sudo visudo  # Add cuckoo to sudoers

# Give necessary permissions
sudo usermod -a -G sudo cuckoo
```

### 2. Directory Structure
```bash
# Create working directories
cd /home/cuckoo/Desktop/
sudo mkdir InstalledPackages
cd InstalledPackages
```

### 3. Package Installation
```bash
# Install required packages
sudo apt-get install autoconf libtool
sudo apt-get install tcpdump apparmor-utils
sudo apt-get install python-dev libfuzzy-dev
sudo apt-get install iptables-persistent
```

## Cuckoo Installation

### 1. YARA Setup
```bash
# Download and install Jansson
sudo wget http://www.digip.org/jansson/releases/jansson-2.9.tar.gz
sudo tar -xaf jansson-2.9.tar.gz
cd jansson-2.9/
sudo ./configure
sudo make && sudo make install

# Download and install YARA
sudo wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
sudo tar -xzf v3.4.0.tar.gz
cd yara-3.4.0/
sudo ./bootstrap.sh
sudo ./configure --enable-cuckoo
sudo make && sudo make install
```

### 2. VirtualBox Installation
```bash
# Add VirtualBox repository
sudo echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
sudo wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -

# Install VirtualBox
sudo apt-get update
sudo apt-get install virtualbox-5.1
```

### 3. Cuckoo Dependencies
```bash
# Install Volatility
sudo wget https://github.com/volatilityfoundation/volatility/archive/master.zip
sudo unzip master.zip
cd volatility-master/
sudo python setup.py build
sudo python setup.py install

# Install M2Crypto
sudo pip install m2crypto==0.24.0

# Install Cuckoo
sudo pip install -U pip setuptools
sudo pip install -U cuckoo
```

## CAPE Installation

### 1. Initial Setup
```bash
# Download CAPE installer
wget https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/installer/cape2.sh
chmod a+x cape2.sh

# Run installer
sudo ./cape2.sh all cape | tee cape.log
```

### 2. Poetry Installation
```bash
cd /opt/CAPEv2/
sudo poetry install

# If you encounter errors
sudo apt install dbus-x11
```

### 3. Database Setup
```bash
# Access PostgreSQL
sudo -u postgres psql

# In PostgreSQL prompt
ALTER DATABASE cape OWNER TO cape;
\q
```

## Configuration

### 1. Network Configuration
```bash
# Enable IP forwarding
sudo echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1

# Configure iptables
sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG
```

### 2. Configuration Files

#### Cuckoo (cuckoo.conf)
```ini
[cuckoo]
version_check = no
reschedule = yes
```

#### CAPE (processing.conf)
```ini
[processing]
apkinfo = yes
misp = yes
idapro = yes
virustotal = yes
```

#### Reporting Configuration (reporting.conf)
```ini
[reporting]
singlefile = yes
misp = yes
elasticsearch = yes,time=3000
mongodb = yes
```

## Virtual Machine Setup

### 1. Windows VM Configuration
```bash
# Create snapshot
sudo VBoxManage snapshot "Win7" take "snapshot1" --pause
sudo VBoxManage controlvm "Win7" poweroff
sudo VBoxManage snapshot "Win7" restorecurrent
```

### 2. Network Setup
- Host-only adapter configuration
- Disable Windows Firewall
- Disable Windows Updates
- Install Python (2.7 for Cuckoo, 3.10.6 32-bit for CAPE)

### 3. Agent Setup
For Cuckoo:
- Install `agent.py` in guest VM
- Configure autostart

For CAPE:
- Rename agent to `pizza.py`
- Place in startup folder

## Network Configuration

### 1. TCPDump Setup
```bash
# Configure TCPDump
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo getcap /usr/sbin/tcpdump
```

### 2. Virtual Network Configuration
```bash
# Create host-only network (VirtualBox)
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
```

## Troubleshooting

### Common Issues

1. **Poetry Installation Errors**
```bash
# Fix Python dependencies
sudo apt install python3-distutils
sudo poetry install
```

2. **Database Connection Issues**
```bash
# Restart PostgreSQL
sudo systemctl restart postgresql
# Set proper permissions
sudo -u postgres psql -c "ALTER DATABASE cape OWNER TO cape;"
```

3. **Virtual Machine Errors**
- Check virtualization settings
- Verify network configuration
- Ensure sufficient resources

### Best Practices

1. **System Maintenance**
   - Regular system updates
   - Database backups
   - Log rotation
   - VM snapshots

2. **Security Configuration**
   - Isolated network environment
   - Regular security updates
   - Access control

3. **Performance Optimization**
   - Resource monitoring
   - Database maintenance
   - VM optimization

## Additional Resources

- [Cuckoo Documentation](https://cuckoo.sh/docs/)
- [CAPE Documentation](https://github.com/kevoreilly/CAPEv2/wiki)
- [VirtualBox Documentation](https://www.virtualbox.org/wiki/Documentation)

---

**Note**: Always maintain backups of your configuration files and virtual machine snapshots. Test each component thoroughly after installation and configuration changes.
