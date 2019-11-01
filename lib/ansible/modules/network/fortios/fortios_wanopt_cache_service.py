#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_wanopt_cache_service
short_description: Designate cache-service for wan-optimization and webcache in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wanopt feature and cache_service category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
        description:
            - FortiOS or FortiGate IP address.
        type: str
        required: false
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: false
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    wanopt_cache_service:
        description:
            - Designate cache-service for wan-optimization and webcache.
        default: null
        type: dict
        suboptions:
            acceptable_connections:
                description:
                    - Set strategy when accepting cache collaboration connection.
                type: str
                choices:
                    - any
                    - peers
            collaboration:
                description:
                    - Enable/disable cache-collaboration between cache-service clusters.
                type: str
                choices:
                    - enable
                    - disable
            device_id:
                description:
                    - Set identifier for this cache device.
                type: str
            dst_peer:
                description:
                    - Modify cache-service destination peer list.
                type: list
                suboptions:
                    auth_type:
                        description:
                            - Set authentication type for this peer.
                        type: int
                    device_id:
                        description:
                            - Device ID of this peer.
                        type: str
                    encode_type:
                        description:
                            - Set encode type for this peer.
                        type: int
                    ip:
                        description:
                            - Set cluster IP address of this peer.
                        type: str
                    priority:
                        description:
                            - Set priority for this peer.
                        type: int
            prefer_scenario:
                description:
                    - Set the preferred cache behavior towards the balance between latency and hit-ratio.
                type: str
                choices:
                    - balance
                    - prefer-speed
                    - prefer-cache
            src_peer:
                description:
                    - Modify cache-service source peer list.
                type: list
                suboptions:
                    auth_type:
                        description:
                            - Set authentication type for this peer.
                        type: int
                    device_id:
                        description:
                            - Device ID of this peer.
                        type: str
                    encode_type:
                        description:
                            - Set encode type for this peer.
                        type: int
                    ip:
                        description:
                            - Set cluster IP address of this peer.
                        type: str
                    priority:
                        description:
                            - Set priority for this peer.
                        type: int
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
   ssl_verify: "False"
  tasks:
  - name: Designate cache-service for wan-optimization and webcache.
    fortios_wanopt_cache_service:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wanopt_cache_service:
        acceptable_connections: "any"
        collaboration: "enable"
        device_id: "<your_own_value>"
        dst_peer:
         -
            auth_type: "7"
            device_id: "<your_own_value>"
            encode_type: "9"
            ip: "<your_own_value>"
            priority: "11"
        prefer_scenario: "balance"
        src_peer:
         -
            auth_type: "14"
            device_id: "<your_own_value>"
            encode_type: "16"
            ip: "<your_own_value>"
            priority: "18"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def filter_wanopt_cache_service_data(json):
    option_list = ['acceptable_connections', 'collaboration', 'device_id',
                   'dst_peer', 'prefer_scenario', 'src_peer']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def wanopt_cache_service(data, fos):
    vdom = data['vdom']
    wanopt_cache_service_data = data['wanopt_cache_service']
    filtered_data = underscore_to_hyphen(filter_wanopt_cache_service_data(wanopt_cache_service_data))

    return fos.set('wanopt',
                   'cache-service',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wanopt(data, fos):

    if data['wanopt_cache_service']:
        resp = wanopt_cache_service(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "wanopt_cache_service": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "acceptable_connections": {"required": False, "type": "str",
                                           "choices": ["any", "peers"]},
                "collaboration": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "device_id": {"required": False, "type": "str"},
                "dst_peer": {"required": False, "type": "list",
                             "options": {
                                 "auth_type": {"required": False, "type": "int"},
                                 "device_id": {"required": False, "type": "str"},
                                 "encode_type": {"required": False, "type": "int"},
                                 "ip": {"required": False, "type": "str"},
                                 "priority": {"required": False, "type": "int"}
                             }},
                "prefer_scenario": {"required": False, "type": "str",
                                    "choices": ["balance", "prefer-speed", "prefer-cache"]},
                "src_peer": {"required": False, "type": "list",
                             "options": {
                                 "auth_type": {"required": False, "type": "int"},
                                 "device_id": {"required": False, "type": "str"},
                                 "encode_type": {"required": False, "type": "int"},
                                 "ip": {"required": False, "type": "str"},
                                 "priority": {"required": False, "type": "int"}
                             }}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    # legacy_mode refers to using fortiosapi instead of HTTPAPI
    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_wanopt(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_wanopt(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
