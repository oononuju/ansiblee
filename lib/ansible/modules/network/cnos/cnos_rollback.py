#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
#
# Copyright (C) 2017 Lenovo, Inc.
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
#
# Module to Rollback Config back to Lenovo Switches
#
# Lenovo Networking
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: cnos_rollback
author: "Anil Kumar Muraleedharan (@amuraleedhar)"
short_description: Roll back the running or startup configuration from a remote
 server on devices running Lenovo CNOS
description:
    - This module allows you to work with switch configurations. It provides a
     way to roll back configurations of a switch from a remote server. This is
     achieved by using startup or running configurations of the target device
     that were previously backed up to a remote server using FTP, SFTP, TFTP,
     or SCP. The first step is to create a directory from where the remote
     server can be reached. The next step is to provide the full file path of
     he backup configuration's location. Authentication details required by the
     remote server must be provided as well.
     By default, this method overwrites the switch's configuration file with
     the newly downloaded file. This module uses SSH to manage network device
     configuration. The results of the operation will be placed in a directory
     named 'results' that must be created by the user in their local directory
     to where the playbook is run. For more information about this module from
     Lenovo and customizing it usage for your use cases, please visit
     U(http://systemx.lenovofiles.com/help/index.jsp?topic=%2Fcom.lenovo.switchmgt.ansible.doc%2Fcnos_rollback.html)
version_added: "2.3"
extends_documentation_fragment: cnos
options:
   configType:
        description:
            - This refers to the type of configuration which will be used for
             the rolling back process. The choices are the running or startup
             configurations. There is no default value, so it will result
             in an error if the input is incorrect.
        required: Yes
        default: Null
        choices: [running-config, startup-config]
   protocol:
        description:
            - This refers to the protocol used by the network device to
              interact with the remote server from where to download the backup
              configuration. The choices are FTP, SFTP, TFTP, or SCP. Any other
              protocols will result in error. If this parameter is not
              specified, there is no default value to be used.
        required: Yes
        default: Null
        choices: [SFTP, SCP, FTP, TFTP]
   rcserverip:
        description:
            - This specifies the IP Address of the remote server from where the
             backup configuration will be downloaded.
        required: Yes
        default: Null
   rcpath:
        description:
            - This specifies the full file path of the configuration file
             located on the remote server. In case the relative path is used as
             the variable value, the root folder for the user of the server
             needs to be specified.
        required: Yes
        default: Null
   serverusername:
        description:
            - Specify username for the server relating to the protocol used.
        required: Yes
        default: Null
   serverpassword:
        description:
            - Specify password for the server relating to the protocol used.
        required: Yes
        default: Null
'''
EXAMPLES = '''
Tasks : The following are examples of using the module cnos_rollback.
 These are written in the main.yml file of the tasks directory.
---

- name: Test Rollback of config - Running config
  cnos_rolback:
      host: "{{ inventory_hostname }}"
      username: "{{ hostvars[inventory_hostname]['ansible_ssh_user'] }}"
      password: "{{ hostvars[inventory_hostname]['ansible_ssh_pass'] }}"
      deviceType: "{{ hostvars[inventory_hostname]['deviceType'] }}"
      enablePassword: "{{ hostvars[inventory_hostname]['enablePassword'] }}"
      outputfile: "./results/test_rollback_{{ inventory_hostname }}_output.txt"
      configType: running-config
      protocol: "sftp"
      serverip: "10.241.106.118"
      rcpath: "/root/cnos/G8272-running-config.txt"
      serverusername: "root"
      serverpassword: "root123"

- name: Test Rollback of config - Startup config
  cnos_rolback:
      host: "{{ inventory_hostname }}"
      username: "{{ hostvars[inventory_hostname]['ansible_ssh_user'] }}"
      password: "{{ hostvars[inventory_hostname]['ansible_ssh_pass'] }}"
      deviceType: "{{ hostvars[inventory_hostname]['deviceType'] }}"
      enablePassword: "{{ hostvars[inventory_hostname]['enablePassword'] }}"
      outputfile: "./results/test_rollback_{{ inventory_hostname }}_output.txt"
      configType: startup-config
      protocol: "sftp"
      serverip: "10.241.106.118"
      rcpath: "/root/cnos/G8272-startup-config.txt"
      serverusername: "root"
      serverpassword: "root123"

- name: Test Rollback of config - Running config - TFTP
  cnos_rolback:
      host: "{{ inventory_hostname }}"
      username: "{{ hostvars[inventory_hostname]['ansible_ssh_user'] }}"
      password: "{{ hostvars[inventory_hostname]['ansible_ssh_pass'] }}"
      deviceType: "{{ hostvars[inventory_hostname]['deviceType'] }}"
      enablePassword: "{{ hostvars[inventory_hostname]['enablePassword'] }}"
      outputfile: "./results/test_rollback_{{ inventory_hostname }}_output.txt"
      configType: running-config
      protocol: "tftp"
      serverip: "10.241.106.118"
      rcpath: "/anil/G8272-running-config.txt"
      serverusername: "root"
      serverpassword: "root123"

- name: Test Rollback of config - Startup config - TFTP
  cnos_rolback:
      host: "{{ inventory_hostname }}"
      username: "{{ hostvars[inventory_hostname]['ansible_ssh_user'] }}"
      password: "{{ hostvars[inventory_hostname]['ansible_ssh_pass'] }}"
      deviceType: "{{ hostvars[inventory_hostname]['deviceType'] }}"
      enablePassword: "{{ hostvars[inventory_hostname]['enablePassword'] }}"
      outputfile: "./results/test_rollback_{{ inventory_hostname }}_output.txt"
      configType: startup-config
      protocol: "tftp"
      serverip: "10.241.106.118"
      rcpath: "/anil/G8272-startup-config.txt"
      serverusername: "root"
      serverpassword: "root123"

'''
RETURN = '''
msg:
  description: Success or failure message
  returned: always
  type: string
  sample: "Config file tranferred to Device"
'''

import sys
import time
import socket
import array
import json
import time
import re
import os
try:
    from ansible.module_utils.network.cnos import cnos
    HAS_LIB = True
except:
    HAS_LIB = False
from ansible.module_utils.basic import AnsibleModule
from collections import defaultdict

# The method below is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded inside it by
# Ansible still belong to the author of the module, and may assign their own
# license to the complete work.
#
# Copyright (C) 2017 Lenovo, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Utility Method to rollback the running config or start up copnfig
# This method supports only SCP or SFTP or FTP or TFTP
def doConfigRollBack(module, prompt, answer):
    host = module.params['host']
    server = module.params['serverip']
    username = module.params['serverusername']
    password = module.params['serverpassword']
    protocol = module.params['protocol'].lower()
    rcPath = module.params['rcpath']
    configType = module.params['configType']
    confPath = rcPath
    retVal = ''

    command = "copy " + protocol + " " + protocol + "://"
    command = command + username + "@" + server + "/" + confPath
    command = command + " " + configType + " vrf management\n"
    cnos.debugOutput(command + "\n")
    # cnos.checkForFirstTimeAccess(module, command, 'yes/no', 'yes')
    cmd = []
    if(protocol == "scp"):
        scp_cmd1 = [{'command': command, 'prompt': 'timeout:', 'answer': '0'}]
        scp_cmd2 = [{'command': '\n', 'prompt': 'Password:',
                     'answer': password}]
        cmd.extend(scp_cmd1)
        cmd.extend(scp_cmd2)
        if(configType == 'startup-config'):
            scp_cmd3 = [{'command': 'y', 'prompt': None, 'answer': None}]
            cmd.extend(scp_cmd3)
        retVal = retVal + str(cnos.run_cnos_commands(module, cmd))
    elif(protocol == "sftp"):
        sftp_cmd = [{'command': command, 'prompt': 'Password:',
                     'answer': password}]
        cmd.extend(sftp_cmd)
        # cnos.debugOutput(configType + "\n")
        if(configType == 'startup-config'):
            sftp_cmd2 = [{'command': 'y', 'prompt': None, 'answer': None}]
            cmd.extend(sftp_cmd2)
        retVal = retVal + str(cnos.run_cnos_commands(module, cmd))
    elif(protocol == "ftp"):
        ftp_cmd = [{'command': command, 'prompt': 'Password:',
                    'answer': password}]
        cmd.extend(ftp_cmd)
        if(configType == 'startup-config'):
            ftp_cmd2 = [{'command': 'y', 'prompt': None, 'answer': None}]
            cmd.extend(ftp_cmd2)
        retVal = retVal + str(cnos.run_cnos_commands(module, cmd))
    elif(protocol == "tftp"):
        command = "copy " + protocol + " " + protocol
        command = command + "://" + server + "/" + confPath
        command = command + " " + configType + " vrf management\n"
        cnos.debugOutput(command)
        tftp_cmd = [{'command': command, 'prompt': None, 'answer': None}]
        cmd.extend(tftp_cmd)
        if(configType == 'startup-config'):
            tftp_cmd2 = [{'command': 'y', 'prompt': None, 'answer': None}]
            cmd.extend(tftp_cmd2)
        retVal = retVal + str(cnos.run_cnos_commands(module, cmd))
    else:
        return "Error-110"

    return retVal
# EOM


def main():
    module = AnsibleModule(
        argument_spec=dict(
            outputfile=dict(required=True),
            host=dict(required=True),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
            enablePassword=dict(required=False, no_log=True),
            deviceType=dict(required=True),
            configType=dict(required=True),
            protocol=dict(required=True),
            serverip=dict(required=True),
            rcpath=dict(required=True),
            serverusername=dict(required=False),
            serverpassword=dict(required=False, no_log=True),),
        supports_check_mode=False)

    outputfile = module.params['outputfile']
    protocol = module.params['protocol'].lower()
    output = ''
    if protocol in ('tftp', 'ftp', 'sftp', 'scp'):
        transfer_status = doConfigRollBack(module, None, None)
    else:
        transfer_status = 'Invalid Protocol option'
    output = output + "\n Config Transfer status \n" + transfer_status

    # Save it into the file
    if '/' in outputfile:
        path = outputfile.rsplit('/', 1)
        # cnos.debugOutput(path[0])
        if not os.path.exists(path[0]):
            os.makedirs(path[0])
    file = open(outputfile, "a")
    file.write(output)
    file.close()

    # need to add logic to check when changes occur or not
    errorMsg = cnos.checkOutputForError(output)
    if(errorMsg is None):
        module.exit_json(changed=True, msg="Config file tranferred to Device")
    else:
        module.fail_json(msg=errorMsg)


if __name__ == '__main__':
    main()
