#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author(s): Abhijeet Kasurde <akasurde@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: vmware_local_role_manager
short_description: Manage local roles on an ESXi host
description:
    - This module can be used to manage local roles on an ESXi host.
version_added: 2.5
author:
- Abhijeet Kasurde (@Akasurde)
notes:
    - Tested on ESXi 6.5
    - Be sure that the ESXi user used for login, has the appropriate rights to create / delete / edit roles
requirements:
    - "python >= 2.6"
    - PyVmomi
options:
  local_role_name:
    description:
    - The local role name to be managed.
    required: True
  local_privilege_ids:
    description:
    - The list of privileges that role needs to have.
    - Please see U(https://docs.vmware.com/en/VMware-vSphere/6.0/com.vmware.vsphere.security.doc/GUID-ED56F3C4-77D0-49E3-88B6-B99B8B437B62.html)
    default: []
  state:
    description:
    - Indicate desired state of the role.
    - If the role already exists when C(state=present), the role info is updated.
    choices: ['present', 'absent']
    default: present
  force_remove:
    description:
    - If set to C(False) then prevents the role from being removed if any permissions are using it.
    default: False
    type: bool
  action:
    description:
    - This parameter is only valid while updating an existing role with privileges.
    - C(add) will add the privileges to the existing privilege list.
    - C(remove) will remove the privileges from the existing privilege list.
    - C(set) will replace the privileges of the existing privileges with user defined list of privileges.
    default: set
    choices: [ add, remove, set ]
    version_added: 2.8
extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = '''
- name: Add local role to ESXi
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    state: present
  delegate_to: localhost

- name: Add local role with privileges to ESXi
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    local_privilege_ids: [ 'Folder.Create', 'Folder.Delete']
    state: present
  delegate_to: localhost

- name: Remove local role from ESXi
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    state: absent
  delegate_to: localhost

- name: Add a privilege to an existing local role
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    local_privilege_ids: [ 'Folder.Create' ]
    action: add
  delegate_to: localhost

- name: Remove a privilege to an existing local role
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    local_privilege_ids: [ 'Folder.Create' ]
    action: remove
  delegate_to: localhost

- name: Set a privilege to an existing local role
  vmware_local_role_manager:
    hostname: '{{ esxi_hostname }}'
    username: '{{ esxi_username }}'
    password: '{{ esxi_password }}'
    local_role_name: vmware_qa
    local_privilege_ids: [ 'Folder.Create' ]
    action: set
  delegate_to: localhost
'''

RETURN = r'''
local_role_name:
    description: Name of local role
    returned: always
    type: string
role_id:
    description: ESXi generated local role id
    returned: always
    type: int
old_privileges:
    description: List of privileges of role before update
    returned: on update
    type: list
new_privileges:
    description: List of privileges of role after update
    returned: on update
    type: list
'''

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import PyVmomi, vmware_argument_spec


class VMwareLocalRoleManager(PyVmomi):
    def __init__(self, module):
        super(VMwareLocalRoleManager, self).__init__(module)
        self.module = module
        self.params = module.params
        self.role_name = self.params['local_role_name']
        self.state = self.params['state']
        self.priv_ids = self.params['local_privilege_ids']
        self.force = not self.params['force_remove']
        self.current_role = None
        self.action = self.params['action']

        if self.content.authorizationManager is None:
            self.module.fail_json(msg="Failed to get local authorization manager settings.",
                                  details="It seems that %s is a vCenter server "
                                          "instead of an ESXi server" % self.params['hostname'])

    def process_state(self):
        local_role_manager_states = {
            'absent': {
                'present': self.state_remove_role,
                'absent': self.state_exit_unchanged,
            },
            'present': {
                'present': self.state_update_role,
                'absent': self.state_create_role,
            }
        }
        try:
            local_role_manager_states[self.state][self.check_local_role_manager_state()]()
        except vmodl.RuntimeFault as runtime_fault:
            self.module.fail_json(msg=runtime_fault.msg)
        except vmodl.MethodFault as method_fault:
            self.module.fail_json(msg=method_fault.msg)
        except Exception as e:
            self.module.fail_json(msg=str(e))

    def check_local_role_manager_state(self):
        auth_role = self.find_authorization_role()
        if auth_role:
            self.current_role = auth_role
            return 'present'
        else:
            return 'absent'

    def find_authorization_role(self):
        desired_role = None
        for role in self.content.authorizationManager.roleList:
            if role.name == self.role_name:
                desired_role = role
        return desired_role

    def state_create_role(self):
        role_id = None
        try:
            role_id = self.content.authorizationManager.AddAuthorizationRole(name=self.role_name,
                                                                             privIds=self.priv_ids)
        except vim.fault.AlreadyExists as e:
            self.module.fail_json(msg="Failed to create a role %s as the user specified role name "
                                      "already exists." % self.role_name,
                                  details=e.msg)
        except vim.fault.InvalidName as e:
            self.module.fail_json(msg="Failed to create a role %s as the user specified role name "
                                      "is empty" % self.role_name,
                                  details=e.msg)
        except vmodl.fault.InvalidArgument as e:
            self.module.fail_json(msg="Failed to create a role %s as the user specified privileges "
                                      "are unknown" % self.role_name,
                                  details=e.msg)
        result = {
            'changed': True,
            'role_id': role_id,
            'privileges': self.priv_ids,
            'local_role_name': self.role_name,
        }
        self.module.exit_json(**result)

    def state_remove_role(self):
        try:
            self.content.authorizationManager.RemoveAuthorizationRole(roleId=self.current_role.roleId,
                                                                      failIfUsed=self.force)
        except vim.fault.NotFound as e:
            self.module.fail_json(msg="Failed to remove a role %s as the user specified role name "
                                      "does not exist." % self.role_name,
                                  details=e.msg)
        except vim.fault.RemoveFailed as e:
            msg = "Failed to remove a role %s as the user specified role name." % self.role_name
            if self.force:
                msg += " Use force_remove as True."

            self.module.fail_json(msg=msg, details=e.msg)
        except vmodl.fault.InvalidArgument as e:
            self.module.fail_json(msg="Failed to remove a role %s as the user specified "
                                      "role is a system role" % self.role_name,
                                  details=e.msg)
        result = {
            'changed': True,
            'role_id': self.current_role.roleId,
            'local_role_name': self.role_name,
        }
        self.module.exit_json(**result)

    def state_exit_unchanged(self):
        role = self.find_authorization_role()
        result = dict(changed=False)

        if role:
            result['role_id'] = role.roleId
            result['local_role_name'] = role.name
            result['old_privileges'] = [priv_name for priv_name in role.privilege]
            result['new_privileges'] = [priv_name for priv_name in role.privilege]

        self.module.exit_json(**result)

    def state_update_role(self):
        current_privileges = self.current_role.privilege

        result = {
            'changed': False,
            'old_privileges': current_privileges,
        }

        changed_privileges = []
        changed = False
        if self.action == 'add':
            # Add to existing privileges
            for priv in self.params['local_privilege_ids']:
                if priv not in current_privileges:
                    changed_privileges.append(priv)
                    changed = True
            if changed:
                changed_privileges.extend(current_privileges)
        elif self.action == 'set':
            # Set given privileges
            # Add system-defined privileges, "System.Anonymous", "System.View", and "System.Read".
            self.params['local_privilege_ids'].extend(['System.Anonymous', 'System.Read', 'System.View'])
            changed_privileges = self.params['local_privilege_ids']

            changes_applied = list(set(current_privileges) ^ set(changed_privileges))
            if changes_applied:
                changed = True
        elif self.action == 'remove':
            # Remove given privileges from existing privileges
            for priv in self.params['local_privilege_ids']:
                if priv in current_privileges:
                    changed = True
                    current_privileges.remove(priv)
            if changed:
                changed_privileges = current_privileges

        if not changed:
            self.state_exit_unchanged()

        try:
            self.content.authorizationManager.UpdateAuthorizationRole(roleId=self.current_role.roleId,
                                                                      newName=self.current_role.name,
                                                                      privIds=changed_privileges)
        except vim.fault.NotFound as e:
            self.module.fail_json(msg="Failed to update Role %s. Please check privileges "
                                      "provided for update" % self.role_name,
                                  details=e.msg)
        except vim.fault.InvalidName as e:
            self.module.fail_json(msg="Failed to update Role %s as role name is empty" % self.role_name,
                                  details=e.msg)
        except vim.fault.AlreadyExists as e:
            self.module.fail_json(msg="Failed to update Role %s." % self.role_name,
                                  details=e.msg)
        except vmodl.fault.InvalidArgument as e:
            self.module.fail_json(msg="Failed to update Role %s as user specified "
                                      "role is system role which can not be changed" % self.role_name,
                                  details=e.msg)
        except vim.fault.NoPermission as e:
            self.module.fail_json(msg="Failed to update Role %s as current session does not"
                                      " have any privilege to update specified role" % self.role_name,
                                  details=e.msg)

        role = self.find_authorization_role()
        result['role_id'] = role.roleId,
        result['changed'] = changed
        result['local_role_name'] = role.name
        result['new_privileges'] = [priv_name for priv_name in role.privilege]

        self.module.exit_json(**result)


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(dict(local_role_name=dict(required=True, type='str'),
                              local_privilege_ids=dict(default=[], type='list'),
                              force_remove=dict(default=False, type='bool'),
                              action=dict(type='str', default='set', choices=[
                                  'add',
                                  'set',
                                  'remove',
                              ]),
                              state=dict(default='present', choices=['present', 'absent'], type='str')))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False)

    vmware_local_role_manager = VMwareLocalRoleManager(module)
    vmware_local_role_manager.process_state()


if __name__ == '__main__':
    main()
