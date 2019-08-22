#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: cs_resourcelimit_facts
short_description: Get facts about resource limits on Apache CloudStack based clouds.
description:
    - Get facts about limits of resources for domains, accounts and projects.
version_added: '2.9'
author: Mauricio Accetturi Carvalho (@accetturi)
options:
  resource_type:
    description:
      - Type of the resource.
    type: str
    required: true
    choices:
      - instance
      - ip_address
      - volume
      - snapshot
      - template
      - network
      - vpc
      - cpu
      - memory
      - primary_storage
      - secondary_storage
    aliases: [ type ]
  domain:
    description:
      - Domain the resource is related to.
    type: str
  account:
    description:
      - Account the resource is related to.
    type: str
  project:
    description:
      - Name of the project the resource is related to.
    type: str
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
- name: Retrieve a resource limit for instances of a domain
  cs_resourcelimit_facts:
    type: instance
    domain: customers
  delegate_to: localhost

- name: Retrieve a resource limit for instances of an account
  cs_resourcelimit_facts:
    type: instance
    account: moserre
    domain: customers
  delegate_to: localhost
'''

RETURN = '''
---
recource_type:
  description: Type of the resource
  returned: success
  type: str
  sample: instance
limit:
  description: Maximum number of the resource.
  returned: success
  type: int
  sample: -1
domain:
  description: Domain the resource is related to.
  returned: success
  type: str
  sample: example domain
account:
  description: Account the resource is related to.
  returned: success
  type: str
  sample: example account
project:
  description: Project the resource is related to.
  returned: success
  type: str
  sample: example project
'''

# import cloudstack common
import os
import time
from ansible.module_utils.six import iteritems
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cloudstack import (
    AnsibleCloudStack,
    cs_argument_spec,
    cs_required_together,
)

RESOURCE_TYPES = {
    'instance': 0,
    'ip_address': 1,
    'volume': 2,
    'snapshot': 3,
    'template': 4,
    'network': 6,
    'vpc': 7,
    'cpu': 8,
    'memory': 9,
    'primary_storage': 10,
    'secondary_storage': 11,
}


class AnsibleCloudStackResourceLimitFacts(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackResourceLimitFacts, self).__init__(module)
        self.returns = {
            'max': 'limit',
        }

    def get_resource_type(self):
        resource_type = self.module.params.get('resource_type')
        return RESOURCE_TYPES.get(resource_type)

    def get_resource_limit(self):
        args = {}
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        args['resourcetype'] = self.get_resource_type()
        resource_limit = self.cs.listResourceLimits(**args)
        if resource_limit:
            return resource_limit['resourcelimit'][0]
        self.module.fail_json(msg="Resource limit type '%s' not found." % self.module.params.get('resource_type'))

    def get_result(self, resource_limit):
        self.result = super(AnsibleCloudStackResourceLimitFacts, self).get_result(resource_limit)
        self.result['resource_type'] = self.module.params.get('resource_type')
        return self.result


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        resource_type=dict(required=True, choices=RESOURCE_TYPES.keys(), aliases=['type']),
        domain=dict(default=None),
        account=dict(default=None),
        project=dict(default=None),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        supports_check_mode=True
    )

    try:
        acs_resource_limit_facts = AnsibleCloudStackResourceLimitFacts(module)
        resource_limit = acs_resource_limit_facts.get_resource_limit()
        result = acs_resource_limit_facts.get_result(resource_limit)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
