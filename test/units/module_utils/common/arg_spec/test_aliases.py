# -*- coding: utf-8 -*-
# Copyright (c) 2021 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.warnings import get_deprecation_messages, get_warning_messages

# id, argument spec, parameters, expected, error, deprecation, warning
ALIAS_TEST_CASES = [
    (
        "alias",
        {'path': {'aliases': ['dir', 'directory']}},
        {
            'dir': '/tmp',
        },
        {
            'dir': '/tmp',
            'path': '/tmp',
        },
        "",
        "",
        "",
    ),
    (
        "alias-duplicate-warning",
        {'path': {'aliases': ['dir', 'directory']}},
        {
            'dir': '/tmp',
            'directory': '/tmp',
        },
        {
            'dir': '/tmp',
            'directory': '/tmp',
            'path': '/tmp',
        },
        "",
        "",
        "Both option path and its alias directory are set",
    ),
    (
        "deprecated-alias",
        {
            'path': {
                'aliases': ['not_yo_path'],
                'deprecated_aliases': [
                    {
                        'name': 'not_yo_path',
                        'version': '1.7',
                    }
                ]
            }
        },
        {'not_yo_path': '/tmp'},
        {
            'path': '/tmp',
            'not_yo_path': '/tmp',
        },
        "",
        "Alias 'not_yo_path' is deprecated.",
        "",
    )
]


@pytest.mark.parametrize(
    ('arg_spec', 'parameters', 'expected', 'error', 'deprecation', 'warning'),
    ((i[1], i[2], i[3], i[4], i[5], i[6]) for i in ALIAS_TEST_CASES),
    ids=[i[0] for i in ALIAS_TEST_CASES]
)
def test_aliases(arg_spec, parameters, expected, error, deprecation, warning):
    v = ArgumentSpecValidator(arg_spec, parameters)
    passed = v.validate()

    assert passed is True
    assert v.validated_parameters == expected

    if not error:
        assert v.error_messages == []
    else:
        assert error in v.error_messages[0]

    deprecations = get_deprecation_messages()
    if not deprecations:
        assert deprecations == ()
    else:
        assert deprecation in get_deprecation_messages()[0]['msg']

    warnings = get_warning_messages()
    if not warning:
        assert warnings == ()
    else:
        assert warning in warnings[0]
