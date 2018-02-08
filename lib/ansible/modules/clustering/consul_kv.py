#!/usr/bin/python
#
# (c) 2015, Steve Gargan <steve.gargan@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
module: consul_kv
short_description: Manipulate entries in the key/value store of a consul cluster
description:
  - Allows the addition, modification and deletion of key/value entries in a
    consul cluster via the agent. The entire contents of the record, including
    the indices, flags and session are returned as 'value'.
  - If the key represents a prefix then Note that when a value is removed, the existing
    value if any is returned as part of the results.
  - See http://www.consul.io/docs/agent/http.html#kv for more details.
requirements:
  - python >= 2.6
  - python-consul
  - requests
version_added: "2.0"
author:
- Steve Gargan (@sgargan)
options:
    state:
        description:
          - The action to take with the supplied key and value. If the state is
            'present', the key contents will be set to the value supplied,
            'changed' will be set to true only if the value was different to the
            current contents. The state 'absent' will remove the key/value pair,
            again 'changed' will be set to true only if the key actually existed
            prior to the removal. An attempt can be made to obtain or free the
            lock associated with a key/value pair with the states 'acquire' or
            'release' respectively. a valid session must be supplied to make the
            attempt changed will be true if the attempt is successful, false
            otherwise.
        choices: [ absent, acquire, present, release ]
        default: present
    key:
        description:
          - The key at which the value should be stored.
        required: yes
    value:
        description:
          - The value should be associated with the given key, required if C(state)
            is C(present).
        required: yes
    recurse:
        description:
          - If the key represents a prefix, each entry with the prefix can be
            retrieved by setting this to C(yes).
        type: bool
        default: 'no'
    session:
        description:
          - The session that should be used to acquire or release a lock
            associated with a key/value pair.
    token:
        description:
          - The token key indentifying an ACL rule set that controls access to
            the key value pair
    cas:
        description:
          - Used when acquiring a lock with a session. If the C(cas) is C(0), then
            Consul will only put the key if it does not already exist. If the
            C(cas) value is non-zero, then the key is only set if the index matches
            the ModifyIndex of that key.
    flags:
        description:
          - Opaque integer value that can be passed when setting a value.
    host:
        description:
          - Host of the consul agent.
        default: localhost
    port:
        description:
          - The port on which the consul agent is running.
        default: 8500
    scheme:
        description:
          - The protocol scheme on which the consul agent is running.
        default: http
        version_added: "2.1"
    validate_certs:
        description:
          - Whether to verify the tls certificate of the consul agent.
        type: bool
        default: 'yes'
        version_added: "2.1"
"""


EXAMPLES = '''
- name: Add or update the value associated with a key in the key/value store
  consul_kv:
    key: somekey
    value: somevalue

- name: Remove a key from the store
  consul_kv:
    key: somekey
    state: absent

- name: Add a node to an arbitrary group via consul inventory (see consul.ini)
  consul_kv:
    key: ansible/groups/dc1/somenode
    value: top_secret

- name: Register a key/value pair with an associated session
  consul_kv:
    key: stg/node/server_birthday
    value: 20160509
    session: "{{ sessionid }}"
    state: acquire
'''

try:
    import consul
    from requests.exceptions import ConnectionError
    python_consul_installed = True
except ImportError:
    python_consul_installed = False

from ansible.module_utils.basic import AnsibleModule


# Note: `python-consul==0.7.2` kv `put` utf-8 encodes data - it cannot be configured
_ENCODING = "utf-8"


def execute(module):

    state = module.params.get('state')

    if state == 'acquire' or state == 'release':
        lock(module, state)
    if state == 'present':
        add_value(module)
    else:
        remove_value(module)


def lock(module, state):

    consul_api = get_consul_api(module)

    session = module.params.get('session')
    key = module.params.get('key')
    value = module.params.get('value')

    if not session:
        module.fail(
            msg='%s of lock for %s requested but no session supplied' %
            (state, key))

    index, existing = consul_api.kv.get(key)

    changed = not existing or (existing and existing['Value'].decode(_ENCODING) != value)
    if changed and not module.check_mode:
        if state == 'acquire':
            changed = consul_api.kv.put(key, value,
                                        cas=module.params.get('cas'),
                                        acquire=session,
                                        flags=module.params.get('flags'))
        else:
            changed = consul_api.kv.put(key, value,
                                        cas=module.params.get('cas'),
                                        release=session,
                                        flags=module.params.get('flags'))

    module.exit_json(changed=changed,
                     index=index,
                     key=key)


def add_value(module):

    consul_api = get_consul_api(module)

    key = module.params.get('key')
    value = module.params.get('value')

    index, existing = consul_api.kv.get(key)

    changed = not existing or (existing and existing['Value'].decode(_ENCODING) != value)
    if changed and not module.check_mode:
        changed = consul_api.kv.put(key, value,
                                    cas=module.params.get('cas'),
                                    flags=module.params.get('flags'))

    if module.params.get('retrieve'):
        index, stored = consul_api.kv.get(key)

    module.exit_json(changed=changed,
                     index=index,
                     key=key,
                     data=stored)


def remove_value(module):
    ''' remove the value associated with the given key. if the recurse parameter
     is set then any key prefixed with the given key will be removed. '''
    consul_api = get_consul_api(module)

    key = module.params.get('key')

    index, existing = consul_api.kv.get(
        key, recurse=module.params.get('recurse'))

    changed = existing is not None
    if changed and not module.check_mode:
        consul_api.kv.delete(key, module.params.get('recurse'))

    module.exit_json(changed=changed,
                     index=index,
                     key=key,
                     data=existing)


def get_consul_api(module, token=None):
    return consul.Consul(host=module.params.get('host'),
                         port=module.params.get('port'),
                         scheme=module.params.get('scheme'),
                         verify=module.params.get('validate_certs'),
                         token=module.params.get('token'))


def test_dependencies(module):
    if not python_consul_installed:
        module.fail_json(msg="python-consul required for this module. "
                             "see http://python-consul.readthedocs.org/en/latest/#installation")


def main():

    module = AnsibleModule(
        argument_spec=dict(
            cas=dict(type='str'),
            flags=dict(type='str'),
            key=dict(type='str', required=True),
            host=dict(type='str', default='localhost'),
            scheme=dict(type='str', default='http'),
            validate_certs=dict(type='bool', default=True),
            port=dict(type='int', default=8500),
            recurse=dict(type='bool'),
            retrieve=dict(type='bool', default=True),
            state=dict(type='str', default='present', choices=['absent', 'acquire', 'present', 'release']),
            token=dict(type='str', no_log=True),
            value=dict(type='str'),
            session=dict(type='str'),
        ),
        supports_check_mode=False,
        required_if=[
            ['state', 'present', ['value']],
        ],
    )

    test_dependencies(module)

    try:
        execute(module)
    except ConnectionError as e:
        module.fail_json(msg='Could not connect to consul agent at %s:%s, error was %s' % (
            module.params.get('host'), module.params.get('port'), e))
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
