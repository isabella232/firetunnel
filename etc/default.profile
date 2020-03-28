# Firetunnel default profile. This file is overwritten when you install a new version of firetunnel.

# Tunnel network address, default 10.10.20.0.
netaddr 10.10.20.0

# Tunnel network mask, default 255.255.255.0
netmask 255.255.255.0

# Tunnel default gateway address, default 10.10.20.1. The gateway is located on the server side.
defaultgw 10.10.20.1

# Tunnel default MTU, calculated by the software if not enabled here.
# mtu 1434.

# NAT enabled by default on the server side. Use nonat below to disable it
# nonat

# Default scrambling/encryption is enabled. Use noscrambling below to disable it
# noscrambling

# Run the program as a Unix daemon, disabled by default.
# daemonize

# Seccomp enabled by default for parent and child processes. See seccomp.child and seccomp.parent configuration below.
# Use noseccomp to disable it.
# noseccomp

# seccomp configuration for parent and child processes if seccomp enabled
seccomp.child    ioctl,write,read,close,open,openat,writev,select,sendto,recvfrom,socket,connect,fstat,stat,getpid,mmap,munmap,mremap,sigreturn,rt_sigprocmask,exit_group,kill,wait4
seccomp.parent sendto,write,read,close,open,openat,writev,ioctl,socket,connect,fstat,stat,getpid,mmap,munmap,mremap,sigreturn,rt_sigprocmask,exit_group,kill,wait4

# DNS servers - not more than 16 are allowed
# Cloudflare
dns 1.1.1.1
# Quad9
dns 9.9.9.9
# CleanBrowsing
dns 185.228.168.168
