#!/bin/sh
# Disposable test sshd: key auth only, non-root user, host keys generated at start.
set -e
ssh-keygen -A >/dev/null
cat /authorized_keys > /home/wguser/.ssh/authorized_keys
chown wguser /home/wguser/.ssh/authorized_keys
chmod 600 /home/wguser/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=no \
  -o AllowUsers=wguser -o AuthorizedKeysFile=/home/wguser/.ssh/authorized_keys
