#!/usr/bin/python

# Copyright: (c) 2019, Andrew Klaus <andrewklaus@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: syspatch

short_description: Manage OpenBSD system patches

version_added: "2.9"

description:
    - "Manage OpenBSD system patches using syspatch"

options:
    apply:
        description:
            - Apply all available system patches
        default: False
        required: false
    revert:
        description:
            - Revert system patches
        required: false
        type: str
        choices: [ all, one ]

author:
    - Andrew Klaus (@precurse)
'''

EXAMPLES = '''
- name: Apply all available system patches
  syspatch:
    apply: true

- name: Revert last patch
  syspatch:
    revert: one

- name: Revert all patches
  syspatch:
    revert: all
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        apply=dict(type='bool', default=False),
        revert=dict(type='str', choices=['all', 'one'])
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[['apply', 'revert']]
    )

    result = syspatch_run(module)

    module.exit_json(**result)


def syspatch_run(module):
    cmd = ['/usr/sbin/syspatch']
    changed = False

    # Setup needed command flags
    if module.params['revert']:
        check_flag = ['-l']

        if module.params['revert'] == 'all':
            run_flag = ['-R']
        else:
            run_flag = ['-r']
    elif module.params['apply']:
        check_flag = ['-c']
        run_flag = []

    rc, out, err = module.run_command(cmd + check_flag)

    if rc != 0:
        module.fail_json(msg="Command %s failed rc=%d, out=%s, err=%s" % (cmd, rc, out, err))

    if len(out) > 0:
        # Changes pending
        change_pending = True
    else:
        # No changes pending
        change_pending = False

    if module.check_mode:
        changed = change_pending
    else:
        rc, out, err = module.run_command(cmd + run_flag)

        # Workaround syspatch ln bug:
        # http://openbsd-archive.7691.n7.nabble.com/Warning-applying-latest-syspatch-td354250.html
        if rc != 0 and err != 'ln: /usr/X11R6/bin/X: No such file or directory\n':
            module.fail_json(msg="Command %s failed rc=%d, out=%s, err=%s" % (cmd, rc, out, err))
        else:
            changed = True

    return dict(
        changed=changed
    )


def main():
    run_module()


if __name__ == '__main__':
    main()
