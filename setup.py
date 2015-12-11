#!/usr/bin/env python

from setuptools import setup, find_packages
from setuptools.command.bdist_rpm import bdist_rpm
from pkg_resources import Requirement, resource_filename
import re
import ast
import os

RPM_REQUIRED_DEPS = "python-pip, rpm-build, gcc, libffi-devel, python-devel, openssl-devel"

def custom_make_spec_file(self):
    spec = self._original_make_spec_file()
    lineDescription = "%description"
    spec.insert(spec.index(lineDescription) - 1, "requires: %s" % RPM_REQUIRED_DEPS)
    return spec

bdist_rpm._original_make_spec_file = bdist_rpm._make_spec_file
bdist_rpm._make_spec_file = custom_make_spec_file

# TODO: Some projects move this to a utils/version.py. We should consider that.
_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('cascade_cli/__init__.py', 'rb') as f:
    matches = _version_re.search(f.read().decode('utf-8'))
    if matches:
        verstr = matches.group(1)
    version = str(ast.literal_eval(verstr))

setup(
    name="cascade-cli",
    version=version,
    url="https://github.com/BlackMesh/cascade-cli", # TODO: Update when published on Github.
    author="BlackMesh",
    author_email="support@blackmesh.com",
    packages=find_packages(),
    package_data={
        '': ['*.ini'],
        'cascade_cli': ['data/ansible.cfg'],
        'cascade_cli': ['data/config.ini'],
        'cascade_cli': ['data/default.conf.j2'],
        'cascade_cli': ['data/drupal.inc'],
        'cascade_cli': ['data/logging.conf'],
        'cascade_cli': ['data/nginx.default.conf.j2'],
    },
    install_requires=[
        "click>=5.1",
        "rpyc>=3.3.0",
        "urllib3>=1.12",
        "termcolor>=1.1.0",
        "PyYAML>=3.11",
        "pyapi-gitlab>=7.8.5",
        "jenkinsapi>=0.2.28",
        "rainbow_logging_handler>=2.2.2",
        "giturlparse.py>=0.0.5",
        "cryptography>=1.0.1",
        "pyopenssl>=0.15.1",
        "ndg-httpsclient>=0.4.0",
        "prettytable>=0.7.2",
    ],
    data_files=[
        ('/etc/cascade-cli/', ["cascade_cli/data/ansible.cfg"]),
        ('/etc/cascade-cli/', ["cascade_cli/data/config.ini"]),
        ('/etc/cascade-cli/', ["cascade_cli/data/default.conf.j2"]),
        ('/etc/cascade-cli/', ["cascade_cli/data/drupal.inc"]),
        ('/etc/cascade-cli/', ["cascade_cli/data/logging.conf"]),
        ('/etc/cascade-cli/', ["cascade_cli/data/nginx.default.conf.j2"]),
    ],
)
