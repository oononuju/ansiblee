#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################
#                WARNING                    #
#############################################
#
# This file is auto generated by the resource
#   module builder playbook.
#
# Do not edit this file manually.
#
# Changes to this file will be over written
#   by the resource module builder.
#
# Changes should be made in the model used to
#   generate this file or in the resource module
#   builder template.
#
#############################################

"""
The module file for nxos_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}

DOCUMENTATION = """
---
module: nxos_interfaces
version_added: 2.9
short_description: 'Manages interface attributes of NX-OS Interfaces'
description: This module manages the interface attributes of NX-OS interfaces.
author: Trishna Guha (@trishnaguha)
notes:
  - Tested against NXOS 7.3.(0)D1(1) on VIRL
options:
  config:
    description: A dictionary of interface options
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of interface, e.g. Ethernet1/1, port-channel10.
        type: str
        required: true
      description:
        description:
          - Interface description.
        type: str
      enabled:
        description:
          - Administrative state of the interface.
            Set the value to C(true) to administratively enable the interface
            or C(false) to disable it
        type: bool
        default: true
      speed:
        description:
          - Interface link speed. Applicable for Ethernet interfaces only.
        type: str
      mode:
        description:
          - Manage Layer2 or Layer3 state of the interface.
            Applicable for Ethernet and port channel interfaces only.
        choices: ['layer2','layer3']
        type: str
      mtu:
        description:
          - MTU for a specific interface. Must be an even number between 576 and 9216.
            Applicable for Ethernet interfaces only.
        type: str
      duplex:
        description:
          - Interface link status. Applicable for Ethernet interfaces only.
        type: str
        choices: ['full', 'half', 'auto']
      ip_forward:
        description:
          - Enable or disable IP forward feature on SVIs.
            Set the value to C(true) to enable  or C(false) to disable.
        type: bool
      fabric_forwarding_anycast_gateway:
        description:
          - Associate SVI with anycast gateway under VLAN configuration mode.
            Applicable for SVI interfaces only.
        type: bool

  state:
    description:
      - The state the configuration should be left in
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""
EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# interface Ethernet1/1
#   description testing
#   mtu 1800

- name: Merge provided configuration with device configuration
  nxos_interfaces:
    config:
      - name: Ethernet1/1
        description: 'Configured by Ansible'
        enabled: True
      - name: Ethernet1/2
        description: 'Configured by Ansible Network'
        enabled: False
    state: merged

# After state:
# ------------
#
# interface Ethernet1/1
#    description Configured by Ansible
#    no shutdown
#    mtu 1800
# interface Ethernet2
#    description Configured by Ansible Network
#    shutdown


# Using replaced

# Before state:
# -------------
#
# interface Ethernet1/1
#    description Interface 1/1
# interface Ethernet1/2

- name: Replaces device configuration of listed interfaces with provided configuration
  nxos_interfaces:
    config:
      - name: Ethernet1/1
        description: 'Configured by Ansible'
        enabled: True
        mtu: 2000
      - name: Ethernet1/2
        description: 'Configured by Ansible Network'
        enabled: False
        mode: layer2
    state: replaced

# After state:
# ------------
#
# interface Ethernet1/1
#   description Configured by Ansible
#   no shutdown
#   mtu 1500
# interface Ethernet2/2
#    description Configured by Ansible Network
#    shutdown
#    switchport


# Using overridden

# Before state:
# -------------
#
# interface Ethernet1/1
#    description Interface Ethernet1/1
# interface Ethernet1/2
# interface mgmt0
#    description Management interface
#    ip address dhcp

- name: Override device configuration of all interfaces with provided configuration
  nxos_interfaces:
    config:
      - name: Ethernet1/1
        enabled: True
      - name: Ethernet1/2
        description: 'Configured by Ansible Network'
        enabled: False
    state: overridden

# After state:
# ------------
#
# interface Ethernet1/1
# interface Ethernet1/2
#    description Configured by Ansible Network
#    shutdown
# interface mgmt0
#    ip address dhcp


# Using deleted

# Before state:
# -------------
#
# interface Ethernet1/1
#    description Interface Ethernet1/1
# interface Ethernet1/2
# interface mgmt0
#    description Management interface
#    ip address dhcp

- name: Delete or return interface parameters to default settings
  nxos_interfaces:
    config:
      - name: Ethernet1/1
    state: deleted

# After state:
# ------------
#
# interface Ethernet1/1
# interface Ethernet1/2
# interface mgmt0
#    description Management interface
#    ip address dhcp


"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['interface Ethernet1/1', 'mtu 1800']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nxos.argspec.interfaces.interfaces import InterfacesArgs
from ansible.module_utils.network.nxos.config.interfaces.interfaces import Interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=InterfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
