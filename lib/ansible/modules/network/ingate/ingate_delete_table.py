#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018, Ingate Systems AB
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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: ingate_delete_table
short_description: Delete all rows in a table.
description:
  - Delete all rows in a table.
version_added: 2.8
extends_documentation_fragment: ingate
options:
  table:
    description: The name of the table.
    required: true
author:
  - Ingate Systems AB (@ingatesystems)
'''

EXAMPLES = '''
- name: Remove all DNS servers
  ingate_delete_table:
    client:
      version: v1
      scheme: http
      address: 192.168.1.1
      username: alice
      password: foobar
    table: misc.dns_servers
'''

RETURN = '''
delete-table:
  description: Information about the deleted row(s)
  returned: success
  type: complex
  contains:
    table:
      description: The name of the table
      returned: success
      type: string
      sample: misc.dns_servers
    data:
      description: Column names/values
      returned: success
      type: complex
      sample: {'number': '2', 'server': '10.48.254.33'}
    id:
      description: The row id
      returned: success
      type: int
      sample: 22
'''

try:
    from ingate import ingatesdk
    HAS_INGATESDK = True
except ImportError:
    HAS_INGATESDK = False


def main():
    argument_spec = ingate_argument_spec(
        table=dict(required=True),
    )
    mutually_exclusive = []
    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive=mutually_exclusive,
                           required_if=required_if,
                           supports_check_mode=False)
    if not HAS_INGATESDK:
        module.fail_json(msg='The Ingate Python SDK module is required')

    result = dict(changed=False)
    try:
        # Create client and authenticate.
        api_client = ingate_create_client(**module.params)

        # Delete all rows in a table.
        table = module.params['table']
        response = api_client.delete_table(table)
        result.update({'delete-table': response})
        if response:
            result['changed'] = True

    except ingatesdk.SdkError as e:
        module.fail_json(msg=str(e))
    module.exit_json(**result)


from ansible.module_utils.basic import *
from ansible.module_utils.network.ingate.common import *

if __name__ == '__main__':
    main()
