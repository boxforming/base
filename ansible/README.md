# Ansible scenarios

## Short descriptions

### Common

#### new-user.yml

Create new user on Debian/Ubuntu host, copy public key, configure passwordless sudo with SSH agent pam and disable root login with password.

## Testing

I'm using Docker Desktop for Mac 4.6 with Debian 11. Start container:

```
docker run --privileged -d --publish 2222:22 -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host --name=sysdeb jrei/systemd-debian:11
```

Linux probably needs different command, something like this (I haven't tested it):

```
docker run -d --publish 2222:22 -v /sys/fs/cgroup/:/sys/fs/cgroup:ro --cap-add SYS_ADMIN --name sysdeb jrei/systemd-debian:11
```

Most of the scripts require regular system with systemd, multiuser, etc… To initialize system, launch container terminal and run:

```
dpkg-reconfigure debconf -f noninteractive -p critical && apt update && apt install openssh-server openssh-client sudo bash python3 -y && sh -c 'echo "\nPermitRootLogin yes" >> /etc/ssh/sshd_config' && systemctl start sshd && sh -c 'echo "root:12345" | chpasswd' && rm /run/nologin
```

When command above will finish you can connect to the Debian instance using ssh to `root@<docker host>` with password `12345`.

`new-user.yml` will help you to create new user on this machine.
