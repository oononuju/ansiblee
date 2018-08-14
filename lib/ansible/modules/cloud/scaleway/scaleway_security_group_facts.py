#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: scaleway_security_group_facts
short_description: Gather facts about the Scaleway security groups available.
description:
  - Gather facts about the Scaleway security groups available.
version_added: "2.7"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment: scaleway
'''

EXAMPLES = r'''
- name: Gather Scaleway security groups facts
  scaleway_security_group_facts:
'''

RETURN = r'''
---
scaleway_security_group_facts:
  description: Response from Scaleway API
  returned: success
  type: complex
  contains:
    "scaleway_security_group_facts": [
        {
            "description": "test-ams",
            "enable_default_security": true,
            "id": "7fcde327-8bed-43a6-95c4-6dfbc56d8b51",
            "name": "test-ams",
            "organization": "3f709602-5e6c-4619-b80c-e841c89734af",
            "organization_default": false,
            "servers": [
                {
                    "id": "12f19bc7-108c-4517-954c-e6b3d0311363",
                    "name": "scw-e0d158"
                }
            ]
        }
    ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.scaleway import (
    Scaleway, ScalewayException, scaleway_argument_spec
)


class ScalewaySecurityGroupFacts(Scaleway):

    def __init__(self, module):
        super(ScalewaySecurityGroupFacts, self).__init__(module)
        self.name = 'security_groups'


def main():
    module = AnsibleModule(
        argument_spec=scaleway_argument_spec(),
        supports_check_mode=True,
    )

    try:
        module.exit_json(
            ansible_facts={'scaleway_security_group_facts': ScalewaySecurityGroupFacts(module).get_resources()}
        )
    except ScalewayException as exc:
        module.fail_json(msg=exc.message)


if __name__ == '__main__':
    main()
