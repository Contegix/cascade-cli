#!/bin/bash
if [ -d /etc/cascade-cli ]; then
    mkdir -p /tmp/cascade-cli
    cp -r /etc/cascade-cli/* /tmp/cascade-cli/.
fi
mkdir -p /var/log/cascade-cli
touch /var/log/cascade-cli/cascade-cli.log

if [ ! -e /etc/cascade-cli/gitlab_rsa.pub ]; then
    ssh-keygen -f /etc/cascade-cli/gitlab_rsa -P ""
fi
