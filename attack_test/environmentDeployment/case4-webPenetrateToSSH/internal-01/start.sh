#!/bin/bash
set -e

# Start rsyslog so auth.log gets written
service rsyslog start

# Start SSH (foreground)
exec /usr/sbin/sshd -D
