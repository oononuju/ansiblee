#
# Copyright (c) 2019 Ericsson AB.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

import json

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.network.common.utils import to_list, ComplexList
from ansible.module_utils.connection import Connection, ConnectionError

_DEVICE_CONFIGS = {}

eric_eccli_provider_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
    'ssh_keyfile': dict(fallback=(env_fallback, ['ANSIBLE_NET_SSH_KEYFILE']), type='path'),
    'authorize': dict(fallback=(env_fallback, ['ANSIBLE_NET_AUTHORIZE']), type='bool'),
    'auth_pass': dict(fallback=(env_fallback, ['ANSIBLE_NET_AUTH_PASS']), no_log=True),
    'timeout': dict(type='int')
}
eric_eccli_argument_spec = {
    'provider': dict(type='dict', options=eric_eccli_provider_spec),
}

eric_eccli_top_spec = {
    'host': dict(removed_in_version=2.9),
    'port': dict(removed_in_version=2.9, type='int'),
    'username': dict(removed_in_version=2.9),
    'password': dict(removed_in_version=2.9, no_log=True),
    'ssh_keyfile': dict(removed_in_version=2.9, type='path'),
    'authorize': dict(fallback=(env_fallback, ['ANSIBLE_NET_AUTHORIZE']), type='bool'),
    'auth_pass': dict(removed_in_version=2.9, no_log=True),
    'timeout': dict(removed_in_version=2.9, type='int')
}
eric_eccli_argument_spec.update(eric_eccli_top_spec)


def get_provider_argspec():
    return eric_eccli_provider_spec


def get_connection(module):
    if hasattr(module, '_eric_eccli_connection'):
        return module._eric_eccli_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get('network_api')
    if network_api == 'cliconf':
        module._eric_eccli_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg='Invalid connection type %s' % network_api)

    return module._eric_eccli_connection


def get_capabilities(module):
    if hasattr(module, '_eric_eccli_capabilities'):
        return module._eric_eccli_capabilities
    try:
        capabilities = Connection(module._socket_path).get_capabilities()
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
    module._eric_eccli_capabilities = json.loads(capabilities)
    return module._eric_eccli_capabilities


def check_args(module, warnings):
    pass


def get_defaults_flag(module):
    connection = get_connection(module)
    try:
        out = connection.get_defaults_flag()
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
    return to_text(out, errors='surrogate_then_replace').strip()


def get_config(module, flags=None):
    flag_str = ' '.join(to_list(flags))

    try:
        return _DEVICE_CONFIGS[flag_str]
    except KeyError:
        connection = get_connection(module)
        try:
            out = connection.get_config(flags=flags)
        except ConnectionError as exc:
            module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
        cfg = to_text(out, errors='surrogate_then_replace').strip()
        _DEVICE_CONFIGS[flag_str] = cfg
        return cfg


def to_commands(module, commands):
    spec = {
        'command': dict(key=True),
        'prompt': dict(),
        'answer': dict()
    }
    transform = ComplexList(spec, module)
    return transform(commands)


def run_commands(module, commands, check_rc=True):
    connection = get_connection(module)
    try:
        return connection.run_commands(commands=commands, check_rc=check_rc)
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc))


def load_config(module, commands):
    connection = get_connection(module)

    try:
        resp = connection.edit_config(commands)
        return resp.get('response')
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc))


def normalize_interface(name):
    """Return the normalized interface name
    """
    if not name:
        return

    def _get_number(name):
        digits = ''
        for char in name:
            if char.isdigit() or char in '/.':
                digits += char
        return digits

    if name.lower().startswith('gi'):
        if_type = 'GigabitEthernet'
    elif name.lower().startswith('te'):
        if_type = 'TenGigabitEthernet'
    elif name.lower().startswith('fa'):
        if_type = 'FastEthernet'
    elif name.lower().startswith('fo'):
        if_type = 'FortyGigabitEthernet'
    elif name.lower().startswith('et'):
        if_type = 'Ethernet'
    elif name.lower().startswith('vl'):
        if_type = 'Vlan'
    elif name.lower().startswith('lo'):
        if_type = 'loopback'
    elif name.lower().startswith('po'):
        if_type = 'port-channel'
    elif name.lower().startswith('nv'):
        if_type = 'nve'
    else:
        if_type = None

    number_list = name.split(' ')
    if len(number_list) == 2:
        if_number = number_list[-1].strip()
    else:
        if_number = _get_number(name)

    if if_type:
        proper_interface = if_type + if_number
    else:
        proper_interface = name

    return proper_interface
