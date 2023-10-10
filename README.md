- Installation
sudo apt update
sudo apt install gcc make linux-headers-$(uname -r)

# Firewall

A very simple linux kernel firewall module.

## Description

This Linux kernel module is designed to act as a very simple firewall leveraging the Netfilter framework in the Linux kernel.

Its purpose is to make decisions on whether to allow or drop packets based on hard-coded protocols and ports.

## Compiling

### Prerequisites

```bash
sudo apt install gcc make linux-headers-$(uname -r)
```

### Compile

* Change directory to cloned repository
* Run make

### Insert module

* sudo insmod firewall.ko

### Remove module

* sudo rmmod firewall