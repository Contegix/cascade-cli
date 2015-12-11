#!/bin/bash
CASCADE=$(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
ln -fs $CASCADE/cascade_cli/cascade_cli.py /usr/bin/cascade-cli
chown root:root /usr/bin/cascade-cli
chmod o-rwx,g+rxs /usr/bin/cascade-cli

if ls $CASCADE/cascade_cli-1.4.*/requires.txt 1> /dev/null 2>&1; then
    REQFILE=$(ls /usr/lib/python2.6/site-packages/cascade_cli-1.4.*/requires.txt)
    pip install -r $REQFILE
fi

pip install git+https://github.com/BlackMesh/pyapi-gitlab-extras.git#egg=pyapi-gitlab-extras

if [ -d /tmp/cascade-cli ]; then
    cp -r /tmp/cascade-cli/* /etc/cascade-cli/.
fi
