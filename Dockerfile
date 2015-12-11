FROM centos:6
MAINTAINER BlackMesh, Inc. <support@blackmesh.com>

RUN rpm -Uvh http://download.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
RUN yum -y install sshpass python-devel python-pip gcc
RUN pip install paramiko PyYAML jinja2 httplib2 ansible
RUN pip install git+https://github.com/BlackMesh/pyapi-gitlab-extras.git#egg=pyapi-gitlab-extras

# TODO: set working directory and install from setup.py
# This Dockerfile is a placeholder
CMD ["cascade-cli", "--server"]
