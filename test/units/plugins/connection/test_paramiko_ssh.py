#
# (c) 2020 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import os
from io import StringIO
import pytest

from ansible.plugins.connection import paramiko_ssh as paramiko_ssh_module
from ansible.plugins.loader import connection_loader
from ansible.playbook.play_context import PlayContext
from ansible.utils.path import makedirs_safe


@pytest.fixture
def play_context():
    play_context = PlayContext()
    play_context.prompt = (
        '[sudo via ansible, key=ouzmdnewuhucvuaabtjmweasarviygqq] password: '
    )

    return play_context


@pytest.fixture()
def in_stream():
    return StringIO()


def test_paramiko_connection_module(play_context, in_stream):
    assert isinstance(
        connection_loader.get('paramiko_ssh', play_context, in_stream),
        paramiko_ssh_module.Connection)


def test_paramiko_connect(play_context, in_stream, mocker):
    paramiko_ssh = connection_loader.get('paramiko_ssh', play_context, in_stream)
    mocker.patch.object(paramiko_ssh, '_connect_uncached')
    connection = paramiko_ssh._connect()

    assert isinstance(connection, paramiko_ssh_module.Connection)
    assert connection._connected is True


def test_create_ssh_directory():
    fixed_permissions = 0o700
    path = os.path.expanduser("~/.ssh")
    makedirs_safe(path, fixed_permissions)
    ssh_dir_stat = os.stat(path)
    assert (ssh_dir_stat.st_mode & 0o7777) == fixed_permissions
