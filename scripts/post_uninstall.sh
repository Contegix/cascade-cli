#!/bin/bash

CASCADE=$(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")

if [ ! -d $CASCADE/cascade_cli ]; then
    rm -f /usr/bin/cascade-cli
else
    ln -fs $CASCADE/cascade_cli/cascade_cli.py /usr/bin/cascade-cli
fi

if [ -d /tmp/cascade-cli ]; then
    cp /tmp/cascade-cli/* /etc/cascade-cli/.
fi
rm -r /tmp/cascade-cli
