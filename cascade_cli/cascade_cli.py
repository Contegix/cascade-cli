#!/usr/bin/env python

import os
import logging, logging.config
import sys
import warnings
from threading import Thread
import rpyc
import ConfigParser

# TODO: requires cleanup. Can put in a dict, and loop through ini entries determinig existance. The methods should probably be moved to some utils package (along with version methods).
# Defaults if config.ini isn't found.
cascade_port = 18861
cascade_path = "/etc/cascade-cli/settings.yml"
log_conf = "/etc/cascade-cli/logging.conf"
ansible_conf = "/etc/cascade-cli/ansible.cfg"
os_user = "root"
allow_public_arrs = True

# TODO: depending on whether we run in server or client is what kind of settings we need...
with open('/etc/cascade-cli/config.ini') as fp:
    parser = ConfigParser.RawConfigParser()
    parser.readfp(fp)

    try:
        ansible_conf = parser.get('cascade', 'ansible_conf')
        os_user = parser.get('cascade', 'os_user')
        log_conf = parser.get('cascade', 'log_conf')
        cascade_port = parser.getint('cascade', 'port')
        cascade_path = parser.get('cascade', 'path')
        allow_public_attrs = parser.getboolean('cascade_protocol_config', 'allow_public_arrs')
    except ConfigParser.NoOptionError as e:
        print e.message

# Configure the logging and set the conf file here so any other file can 
# log. This must be done before any other module is imported so that module
# can also log to it.
logging.config.fileConfig(log_conf)
logger = logging.getLogger("root")
logger.setLevel(logging.WARNING)

# The environment variable has to be set before the Ansible wrapper is imported.
os.environ['ANSIBLE_CONFIG'] = ansible_conf
os.environ['USER'] = os_user

# Define server services.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from config import CascadeConfig
    
    # Expose our config so clients can access it.
    class CascadeService(rpyc.Service):
        class exposed_CascadeConfig(CascadeConfig):
            # Intentionally passing so that we can just expose the whole class.
            pass
        class exposed_CascadeBuffer(object):
            def __init__(self, callback):
                self.cbuffer = None
                self.callback = rpyc.async(callback)
                self.thread = Thread(target = self.exposed_dumpbuffer)
                self.thread.start()
            def exposed_stop(self):
                """ Stop should be exposed so the client can join threads. """
                self.thread.join()
            def exposed_dumpbuffer(self):
                """ If there's a buffer perform callback. """
                if self.cbuffer:
                    self.callback(self.cbuffer)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")

    def server():
        from rpyc.utils.server import ThreadedServer
        protocol_config = { "allow_public_attrs": allow_public_arrs }
        server = ThreadedServer(
            CascadeService, 
            port=cascade_port, 
            protocol_config=protocol_config,
            logger=logger
        )
        server.start()

    def client():
        import cli
        cli.cli()
        cli.cleanup()

    def main():
        server() if "--server" in sys.argv else client()

    if __name__ == "__main__":
        main()
