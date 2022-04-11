# Ansible scenarios

## Short descriptions

### Common

#### new-user.yml

This playbook will create user on empty linux server with ssh root account,
copy ssh public key, configure passwordless sudo with agent,
then checks server access and disable root password access via ssh.

<details>
<summary>Usage</summary>

If you need to use password for ssh login, sshpass must be installed somewhere in your $PATH

 * shell (recommended) https://github.com/boxforming/sshpass.sh
 * binary (not recommended) https://github.com/hudochenkov/homebrew-sshpass

HOWTO

1. Add your new server to the inventory

variables:

 * `new_user` - username for new user
 * `new_pass` - encoded password

2.1. If your hoster put public key to /root/.ssh/authorized_keys, launch

```
ansible-playbook -i inventory.ini user.yml --extra-vars "new_user=username new_pass=''" --user root --key-file ~/.ssh/<private_key_file> -l <host_alias>
```

2.2. If your hoster have root account with password authentication via ssh, launch

```
ansible-playbook -i inventory.ini user.yml --extra-vars "new_user=username new_pass=''" --user root --ask-pass -l <host_alias>
```

I don't recommend you to have private key path or root password in inventory,
but I cannot deny you to shoot your own leg by providing such variables:

# can conflict with generated private key file for that host

`<host_alias> ansible_ssh_private_key_file=~/.ssh/<private_key_file>`

# what can go wrong?

`<host_alias> ansible_ssh_user=root ansible_ssh_pass=<root_password>`


# additionally you can define different host and port

`<host_alias> ansible_host=host ansible_port=2222`

`ansible_host` and `ansible_port` is optional, useful if host != host_alias or testing using docker with ssh port 2222

</details>

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
