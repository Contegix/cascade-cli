#!/bin/bash
if [ -d /tmp/cascade-cli ]; then
    rm -r /tmp/cascade-cli
fi
mkdir /tmp/cascade-cli
cp -r /etc/cascade-cli/* /tmp/cascade-cli/.
