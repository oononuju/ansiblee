# -*- coding: utf-8 -*-
# Copyright (c) 2018 Ansible Project
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils._text import to_native
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.common.collections import is_iterable

from ansible.module_utils.six import (
    binary_type,
    integer_types,
    text_type,
)

# Python2 & 3 way to get NoneType
NoneType = type(None)

PASS_VARS = {
    'check_mode': 'check_mode',
    'debug': '_debug',
    'diff': '_diff',
    'keep_remote_files': '_keep_remote_files',
    'module_name': '_name',
    'no_log': 'no_log',
    'remote_tmp': '_remote_tmp',
    'selinux_special_fs': '_selinux_special_fs',
    'shell_executable': '_shell',
    'socket': '_socket_path',
    'string_conversion_action': '_string_conversion_action',
    'syslog_facility': '_syslog_facility',
    'tmpdir': '_tmpdir',
    'verbosity': '_verbosity',
    'version': 'ansible_version',
}

DEFAULT_LEGAL_PARAMS = ['_ansible_%s' % k for k in PASS_VARS]


def handle_aliases(argument_spec, params, legal_inputs=None):
    """Return a two items. The first is a dictionary of aliases, the second is
    a list of legal inputs, or None."""

    if legal_inputs is None:
        legal_inputs = DEFAULT_LEGAL_PARAMS[:]
    elif legal_inputs:
        legal_inputs = legal_inputs[:]
    aliases_results = {}  # alias:canon

    for (k, v) in argument_spec.items():
        legal_inputs.append(k)
        aliases = v.get('aliases', None)
        default = v.get('default', None)
        required = v.get('required', False)
        if default is not None and required:
            # not alias specific but this is a good place to check this
            raise ValueError("internal error: required and default are mutually exclusive for %s" % k)
        if aliases is None:
            continue
        if not is_iterable(aliases) or isinstance(aliases, (binary_type, text_type)):
            raise TypeError('internal error: aliases must be a list or tuple')
        for alias in aliases:
            legal_inputs.append(alias)
            aliases_results[alias] = k
            if alias in params:
                params[k] = params[alias]

    return aliases_results, legal_inputs


def _return_datastructure_name(obj):
    """Return native stringified values from datastructures.
    For use with removing sensitive values pre-jsonification."""

    if isinstance(obj, (text_type, binary_type)):
        if obj:
            yield to_native(obj, errors='surrogate_or_strict')
        return
    elif isinstance(obj, Mapping):
        for element in obj.items():
            for subelement in _return_datastructure_name(element[1]):
                yield subelement
    elif is_iterable(obj):
        for element in obj:
            for subelement in _return_datastructure_name(element):
                yield subelement
    elif isinstance(obj, (bool, NoneType)):
        # This must come before int because bools are also ints
        return
    elif isinstance(obj, tuple(list(integer_types) + [float])):
        yield to_native(obj, nonstring='simplerepr')
    else:
        raise TypeError('Unknown parameter type: %s, %s' % (type(obj), obj))


def list_no_log_values(argument_spec, params):
    """Return list of no log values and deprecations"""

    no_log_values = set()
    for arg_name, arg_opts in argument_spec.items():

        if arg_opts.get('no_log', False):
            # Find the value for the no_log'd param
            no_log_object = params.get(arg_name, None)

            if no_log_object:
                no_log_values.update(_return_datastructure_name(no_log_object))

    return no_log_values


def list_deprecations(argument_spec, params):
    """Return a list of deprecations"""

    deprecations = list()
    for arg_name, arg_opts in argument_spec.items():
        if arg_opts.get('removed_in_version') is not None and arg_name in params:
            deprecations.append({
                'msg': "Param '%s' is deprecated. See the module docs for more information" % arg_name,
                'version': arg_opts.get('removed_in_version')
            })

    return deprecations
