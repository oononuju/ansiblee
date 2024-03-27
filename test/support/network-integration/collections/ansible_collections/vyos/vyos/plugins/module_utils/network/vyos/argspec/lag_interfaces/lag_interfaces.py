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
The arg spec for the vyos_lag_interfaces module
"""
from __future__ import annotations


class Lag_interfacesArgs(object):  # pylint: disable=R0903
    """The arg spec for the vyos_lag_interfaces module"""

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        "config": {
            "elements": "dict",
            "options": {
                "arp_monitor": {
                    "options": {
                        "interval": {"type": "int"},
                        "target": {"type": "list"},
                    },
                    "type": "dict",
                },
                "hash_policy": {
                    "choices": ["layer2", "layer2+3", "layer3+4"],
                    "type": "str",
                },
                "members": {
                    "elements": "dict",
                    "options": {"member": {"type": "str"}},
                    "type": "list",
                },
                "mode": {
                    "choices": [
                        "802.3ad",
                        "active-backup",
                        "broadcast",
                        "round-robin",
                        "transmit-load-balance",
                        "adaptive-load-balance",
                        "xor-hash",
                    ],
                    "type": "str",
                },
                "name": {"required": True, "type": "str"},
                "primary": {"type": "str"},
            },
            "type": "list",
        },
        "state": {
            "choices": ["merged", "replaced", "overridden", "deleted"],
            "default": "merged",
            "type": "str",
        },
    }  # pylint: disable=C0301
