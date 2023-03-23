#!/usr/bin/python
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: check_mode_attribute_6
short_description: Test for check mode attribute 6
description: Test for check mode attribute 6.
author:
  - Ansible Core Team
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    # Everything is correct: docs says partial support *with details*, code claims (at least some) support
    support: partial
    details: Some details.
  diff_mode:
    support: none
  platform:
    platforms: all
'''

EXAMPLES = '''#'''
RETURN = ''''''

from ansible.module_utils.basic import AnsibleModule


if __name__ == '__main__':
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=True)
    module.exit_json()
