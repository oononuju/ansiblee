#!/usr/bin/python
#
# (c) 2017, Daniel Korn <korndaniel1@gmail.com>
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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''

module: manageiq_user

short_description: Management of users in ManageIQ
extends_documentation_fragment: manageiq
version_added: '2.4'
author: Daniel Korn (@dkorn)
description:
  - The manageiq_user module supports adding, updating and deleting users in ManageIQ.

options:
  state:
    description:
      - absent - user should not exist, present - user should be.
    required: False
    choices: ['absent', 'present']
    default: 'present'
  userid:
    description:
      - The unique userid in manageiq, often mentioned as username.
    required: true
  name:
    description:
      - The users' full name.
    required: false
    default: null
  password:
    description:
      - The users' password.
    required: false
    default: null
  group:
    description:
      - The name of the group to which the user belongs.
    required: false
    default: null
  email:
    description:
      - The users' E-mail address.
    required: false
    default: null
'''

EXAMPLES = '''
- name: Create a new user in ManageIQ
  manageiq_user:
    userid: 'jdoe'
    name: 'Jane Doe'
    password: 'VerySecret'
    group: 'EvmGroup-user'
    email: 'jdoe@example.com'
    miq:
      url: 'http://example.com:3000'
      username: 'admin'
      password: 'smartvm'
      verify_ssl: False
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.manageiq import (
    check_client,
    ManageIQ,
)


class ManageIQUser(object):
    """
        object to execute user management operations in manageiq
    """

    def __init__(self, manageiq):
        self.manageiq = manageiq
        self.module = self.manageiq.module
        self.api_url = self.manageiq.api_url

    def group_id(self, group):
        """ Search for group id by group name

        Returns:
            the group id, or send a module Fail signal if group not found
        """
        group_obj = self.manageiq.find_collection_resource_by('groups', description=group)
        if not group_obj:  # group doesn't exist
            self.module.fail_json(
                msg="Group {group} does not exist in manageiq".format(group=group))

        return group_obj['id']

    def user(self, userid):
        """ Search for user object by userid

        Returns:
            the user, or None if group not found
        """
        return self.manageiq.find_collection_resource_by('users', userid=userid)

    def compare_user(self, user, name, group_id, password, email):
        """ Compare user fields againse new values

        Returns:
            true if user fields need update, false o/w
        """
        compare = (
            (name and user['name'] != name) or
            (password is not None) or
            (email and user['email'] != email) or
            (group_id and user['group']['id'] != group_id)
        )

        return compare

    def delete_user(self, userid):
        """Deletes a user from manageiq.

        Returns:
            a short message describing the operation executed.
        """
        user = self.user(userid)

        try:
            url = '{api_url}/users/{user_id}'.format(api_url=self.api_url, user_id=user['id'])
            result = self.manageiq.client.post(url, action='delete')
        except Exception as e:
            self.module.fail_json(msg="Failed to delete user {userid}: {error}".format(userid=userid, error=e))

        return dict(changed=True, msg=result['message'])

    def edit_user(self, user, name, group, password, email):
        """Edit a user from manageiq.

        Returns:
            a short message describing the operation executed.
        """
        group_id = None
        url = '{api_url}/users/{user_id}'.format(api_url=self.api_url, user_id=user['id'])

        resource = dict(userid=user['userid'])
        if group is not None:
            group_id = self.group_id(group)
            resource['group'] = dict(id=group_id)
        if name is not None:
            resource['name'] = name
        if password is not None:
            resource['password'] = password
        if email is not None:
            resource['email'] = email

        # check if we need to update
        if not self.compare_user(user, name, group_id, password, email):
            return dict(
                changed=False,
                msg="User {userid} is not changed.".format(userid=user['userid']))

        # try to update user
        try:
            result = self.manageiq.client.post(url, action='edit', resource=resource)
        except Exception as e:
            self.module.fail_json(msg="Failed to update user {userid}: {error}".format(userid=user['userid'], error=e))

        return dict(
            changed=True,
            msg="Successfully updated the user {userid}: {user_details}".format(userid=user['userid'], user_details=result))

    def create_user(self, userid, name, group, password, email):
        """Creates the user in manageiq.

        Returns:
            the created user id, name, created_on timestamp,
            updated_on timestamp, userid and current_group_id
        """
        # check that we have all fields
        for key, value in dict(name=name, group=group, password=password).items():
            if value in (None, ''):
                self.module.fail_json(msg="missing required argument: {}".format(key))

        # get group id
        group_id = self.group_id(group)

        # create new user
        url = '{api_url}/users'.format(api_url=self.api_url)
        resource = {'userid': userid, 'name': name, 'password': password, 'group': {'id': group_id}}
        if email is not None:
            resource['email'] = email

        try:
            result = self.manageiq.client.post(url, action='create', resource=resource)
        except Exception as e:
            self.module.fail_json(msg="Failed to create user {userid}: {error}".format(userid=userid, error=e))

        return dict(
            changed=True,
            msg="Successfully created the user {userid}: {user_details}".format(userid=userid, user_details=result['results']))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            miq=dict(required=True, type='dict'),
            userid=dict(required=True, type='str'),
            name=dict(),
            password=dict(no_log=True),
            group=dict(),
            email=dict(),
            state=dict(choices=['absent', 'present'], default='present')
        ),
    )

    userid = module.params['userid']
    name = module.params['name']
    password = module.params['password']
    group = module.params['group']
    email = module.params['email']
    state = module.params['state']

    manageiq = ManageIQ(module)
    manageiq_user = ManageIQUser(manageiq)

    user = manageiq_user.user(userid)

    # user should not exist
    if state == "absent":
        # if we do not have a user, nothing to do
        if not user:
            res_args = dict(
                changed=False,
                msg="User {userid}: does not exist in manageiq".format(userid=userid),
            )
        # if we have a user, delete it
        else:
            res_args = manageiq_user.delete_user(userid)

    # user shoult exist
    if state == "present":
        # if we do not have a user, create it
        if not user:
            res_args = manageiq_user.create_user(userid, name, group, password, email)
        # if we have a user, edit it
        else:
            res_args = manageiq_user.edit_user(user, name, group, password, email)

    module.exit_json(**res_args)


if __name__ == "__main__":
    main()
