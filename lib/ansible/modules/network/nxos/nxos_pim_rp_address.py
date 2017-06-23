#!/usr/bin/python
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

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community',
}


DOCUMENTATION = '''
---
module: nxos_pim_rp_address
extends_documentation_fragment: nxos
version_added: "2.2"
short_description: Manages configuration of an PIM static RP address instance.
description:
  - Manages configuration of an Protocol Independent Multicast (PIM) static
    rendezvous point (RP) address instance.
author: Gabriele Gerbino (@GGabriele)
notes:
  - C(state=absent) remove the whole rp-address configuration, if existing.
options:
  rp_address:
    description:
      - Configures a Protocol Independent Multicast (PIM) static
        rendezvous point (RP) address. Valid values are
        unicast addresses.
    required: true
  group_list:
    description:
      - Group range for static RP. Valid values are multicast addresses.
    required: false
    default: null
  prefix_list:
    description:
      - Prefix list policy for static RP. Valid values are prefix-list
        policy names.
    required: false
    default: null
  route_map:
    description:
      - Route map policy for static RP. Valid values are route-map
        policy names.
    required: false
    default: null
  bidir:
    description:
      - Group range is treated in PIM bidirectional mode.
    required: false
    choices: ['true','false']
    default: null
'''
EXAMPLES = '''
- nxos_pim_rp_address:
    rp_address: "10.1.1.20"
    state: present
'''

RETURN = '''
commands:
    description: commands sent to the device
    returned: always
    type: list
    sample: ["router bgp 65535", "vrf test", "router-id 1.1.1.1"]
'''


from ansible.module_utils.nxos import get_config, load_config
from ansible.module_utils.nxos import nxos_argument_spec, check_args
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.netcfg import CustomNetworkConfig


def get_value(config, module):
    value_list = []
    splitted_config = config.splitlines()
    for line in splitted_config:
        tmp = {}
        if 'ip pim rp-address' in line:
            splitted_line = line.split()
            tmp['rp_address'] = splitted_line[3]
            if len(splitted_line) > 5:
                value = splitted_line[5]
                if splitted_line[4] == 'route-map':
                    tmp['route_map'] = value
                elif splitted_line[4] == 'prefix-list':
                    tmp['prefix_list'] = value
                elif splitted_line[4] == 'group-list':
                    tmp['group_list'] = value
            tmp['bidir'] = 'bidir' in line
            value_list.append(tmp)
    return value_list


def get_existing(module, args):
    existing = {}
    config = str(get_config(module))
    existing = get_value(config, module)
    return existing


def apply_key_map(key_map, table):
    new_dict = {}
    for key, value in table.items():
        new_key = key_map.get(key)
        if new_key:
            new_dict[new_key] = value
    return new_dict


def state_present(module, existing, proposed, candidate):
    address = module.params['rp_address']
    command = 'ip pim rp-address {0}'.format(address)
    commands = build_command(proposed, command)
    if commands:
        candidate.add(commands, parents=[])


def build_command(param_dict, command):
    for param in ['group_list', 'prefix_list', 'route_map']:
        if param_dict.get(param):
            command += ' {0} {1}'.format(
                param.replace('_', '-'), param_dict.get(param))
    if param_dict.get('bidir'):
        command += ' bidir'
    return [command]


def state_absent(module, existing, proposed, candidate):
    address = module.params['rp_address']
    commands = list()
    for each in existing:
        if each.get('rp_address') == address:
            command = 'no ip pim rp-address {0}'.format(address)
            if each.get('group_list'):
                commands = build_command(each, command)
            else:
                commands = [command]
    if commands:
        candidate.add(commands, parents=[])


def main():
    argument_spec = dict(
        rp_address=dict(required=True, type='str'),
        group_list=dict(required=False, type='str'),
        prefix_list=dict(required=False, type='str'),
        route_map=dict(required=False, type='str'),
        bidir=dict(required=False, type='bool'),
        state=dict(choices=['present', 'absent'], default='present', required=False),
    )
    argument_spec.update(nxos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive=[['group_list', 'route_map'],
                                               ['group_list', 'prefix_list'],
                                               ['route_map', 'prefix_list']],
                           supports_check_mode=True)

    warnings = list()
    check_args(module, warnings)
    result = {'changed': False, 'commands': [], 'warnings': warnings}


    state = module.params['state']

    args = [
        'rp_address',
        'group_list',
        'prefix_list',
        'route_map',
        'bidir'
    ]

    existing = get_existing(module, args)
    proposed_args = dict((k, v) for k, v in module.params.items()
                         if v is not None and k in args)

    proposed = {}
    for key, value in proposed_args.items():
        if key != 'rp_address':
            if str(value).lower() == 'true':
                value = True
            elif str(value).lower() == 'false':
                value = False
            for each in existing:
                if each.get(key) != value:
                    proposed[key] = value

    candidate = CustomNetworkConfig(indent=3)
    if state == 'present' and proposed:
        state_present(module, existing, proposed, candidate)
    elif state == 'absent':
        state_absent(module, existing, proposed, candidate)

    if candidate:
        candidate = candidate.items_text()
        result['commands'] = candidate
        result['changed'] = True
        load_config(module, candidate)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
