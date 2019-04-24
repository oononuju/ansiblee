#!/usr/bin/python
#
# Copyright (c) 2019 Yuwei Zhou, <yuwzho@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_lock
version_added: "2.9"
short_description: Manage Azure locks.
description:
    - Create, delete an Azure lock.
options:
    name:
        description:
            - Name of the lock.
        required: true
    resource_id:
        description:
            - Id of the resource where need to manage the lock.
            - Get this via facts module.
            - Cannot be set mutal with C(resource_group).
            - Manage subscription if both C(resource_id) and C(resource_group) not defined.
    resource_group:
        description:
            - Resource group name where need to manage the lock.
            - The lock is in the resource group level.
            - Cannot be set mutal with C(resource_id).
            - Manage subscription if both C(resource_id) and C(resource_group) not defined.
    state:
        description:
            - Assert the state of the lock.
            - Use C(present) to create or update a lock and C(absent) to delete a lock.
        default: present
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure

author:
    - "Yuwei Zhou (@yuwzho)"

'''

EXAMPLES = '''
'''

RETURN = '''
'''  # NOQA

from ansible.module_utils.common.dict_transformations import _camel_to_snake
from ansible.module_utils.azure_rm_common import AzureRMModuleBase, format_resource_id

try:
    from msrestazure.tools import parse_resource_id
    from msrestazure.azure_exceptions import CloudError
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMLock(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            resource_group=dict(type='str'),
            resource_id=dict(type='str'),
            level=dict(type='str', choices=['not_specified', 'can_not_delete', 'read_only'], required=True)
        )

        self.results = dict(
            changed=False,
            id=None
        )

        mutually_exclusive = [['resource_group', 'resource_id']]

        self.name = None
        self.state = None
        self.level = None
        self.resource_group = None
        self.resource_id = None

        super(AzureRMLock, self).__init__(self.module_arg_spec, supports_check_mode=True, mutually_exclusive=mutually_exclusive, supports_tags=False)

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec.keys():
            setattr(self, key, kwargs[key])

        changed = False
        # construct scope id
        scope = self.get_scope()
        lock = self.get_lock(scope)
        if self.state == 'present':
            lock_level = getattr(self.lock_models.LockLevel, self.level)
            if not lock:
                changed = True
                lock = self.lock_models.ManagementLockObject(level=lock_level)
            elif lock.level != lock_level:
                    self.log('Lock level changed')
                    lock.level = lock_level
                    changed = True
            if not self.check_mode:
                lock = self.create_or_update_lock(scope, lock)
                self.results['id'] = lock.id
        elif lock:
            changed = True
            if not self.check_mode:
                self.delete_lock(scope)
        self.results['changed'] = changed
        return self.results

    def delete_lock(self, scope):
        try:
            return self.lock_client.management_locks.delete_by_scope(scope, self.name)
        except CloudError as exc:
            self.fail('Error when deleting lock {0} for {1}: {2}'.format(self.name, scope, exc.message)) 

    def create_or_update_lock(self, scope, lock):
        try:
            return self.lock_client.management_locks.create_or_update_by_scope(scope, self.name, lock)
        except CloudError as exc:
            self.fail('Error when creating or updating lock {0} for {1}: {2}'.format(self.name, scope, exc.message))

    def get_lock(self, scope):
        try:
            return self.lock_client.management_locks.get_by_scope(scope, self.name)
        except CloudError as exc:
            if exc.status_code in [404]:
                return None
            self.fail('Error when getting lock {0} for {1}: {2}'.format(self.name, scope, exc.message))

    def get_scope(self):
        '''
        Get the resource scope of the lock management.
        '/subscriptions/{subscriptionId}' for subscriptions,
        '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}' for resource groups,
        '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{namespace}/{resourceType}/{resourceName}' for resources.
        '''
        if self.resource_id:
            return self.resource_id
        elif self.resource_group:
            return '/subscriptions/{0}/resourcegroups/{1}'.format(self.subscription_id, self.resource_group)
        else:
            return '/subscriptions/{0}'.format(self.subscription_id)


def main():
    AzureRMLock()


if __name__ == '__main__':
    main()
