#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2019, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: ios_bgp
version_added: "2.8"
author: "Nilashish Chakraborty (@nilashishc)"
short_description: Configure global BGP protocol settings on Cisco IOS.
description:
  - This module provides configuration management of global BGP parameters
    on devices running Cisco IOS
notes:
  - Tested against Cisco IOS Version 15.6(3)M2
options:
  config:
    description:
      - Specifies the BGP related configuration.
    suboptions:
      bgp_as:
        description:
          - Specifies the BGP Autonomous System (AS) number to configure on the device.
        type: int
        required: true
      router_id:
        description:
          - Configures the BGP routing process router-id value.
        default: null
      log_neighbor_changes:
        description:
          - Enable/disable logging neighbor up/down and reset reason.
        type: bool
      neighbors:
        description:
          - Specifies BGP neighbor related configurations.
        suboptions:
          neighbor:
            description:
              - Neighbor router address.
            required: True
          remote_as:
            description:
              - Remote AS of the BGP neighbor to configure.
            type: int
            required: True
          update_source:
            description:
              - Source of the routing updates.
          password:
            description:
              - Password to authenticate the BGP peer connection.
          enabled:
            description:
              - Administratively shutdown or enable a neighbor.
            type: bool
          description:
            description:
              - Neighbor specific description.
          ebgp_multihop:
            description:
              - Specifies the maximum hop count for EBGP neighbors not on directly connected networks.
              - The range is from 1 to 255.
            type: int
          peer_group:
            description:
              - Name of the peer group that the neighbor is a member of.
          timers:
            description:
              - Specifies BGP neighbor timer related configurations.
            suboptions:
              keepalive:
                description:
                  - Frequency (in seconds) with which the device sends keepalive messages to its peer.
                  - The range is from 0 to 65535.
                type: int
                required: True
              holdtime:
                description:
                  - Interval (in seconds) after not receiving a keepalive message that IOS declares a peer dead.
                  - The range is from 0 to 65535.
                type: int
                required: True
              min_neighbor_holdtime:
                description:
                  - Interval (in seconds) specifying the minimum acceptable hold-time from a BGP neighbor.
                  - The minimum acceptable hold-time must be less than, or equal to, the interval specified in the holdtime argument.
                  - The range is from 0 to 65535.
                type: int
          local_as:
            description:
              - The local AS number for the neighbor.
            type: int
      networks:
        description:
          - Specify networks to announce via BGP.
        suboptions:
          prefix:
            description:
              - Network ID to announce via BGP.
            required: True
          masklen:
            description:
              - Subnet mask length for the network to announce(e.g, 8, 16, 24, etc.).
          route_map:
            description:
              - Route map to modify the attributes.
      address_family:
        description:
          - Specifies BGP address family related configurations.
        suboptions:
          afi:
            description:
              - Type of address family to configure.
            choices:
              - ipv4
              - ipv6
            required: True
          safi:
            description:
              - Specifies the type of cast for the address family.
            choices:
              - flowspec
              - unicast
              - multicast
              - labeled-unicast
            default: unicast
          redistribute:
            description:
              - Specifies the redistribute information from another routing protocol.
            suboptions:
              protocol:
                description:
                  - Specifies the protocol for configuring redistribute information.
                choices: ['ospf', 'ospfv3', 'eigrp', 'isis', 'static', 'connected', 'odr', 'lisp', 'mobile', 'rip']
                required: True
              id:
                description:
                  - Identifier for the routing protocol for configuring redistribute information.
                  - Valid for protocols 'ospf', 'ospfv3' and 'eigrp'.
              metric:
                description:
                  - Specifies the metric for redistributed routes.
              route_map:
                description:
                  - Specifies the route map reference.
          networks:
            description:
              - Specify networks to announce via BGP.
            suboptions:
              prefix:
                description:
                  - Network ID to announce via BGP.
                required: True
              masklen:
                description:
                  - Subnet mask length for the network to announce(e.g, 8, 16, 24, etc.).
              route_map:
                description:
                  - Route map to modify the attributes.
          neighbors:
            description:
              - Specifies BGP neighbor related configurations in Address Family configuration mode.
            suboptions:
              neighbor:
                description:
                  - Neighbor router address.
                required: True
              advertisement_interval:
                description:
                  - Minimum interval between sending BGP routing updates for this neighbor.
                type: int
              route_reflector_client:
                description:
                  - Specify a neighbor as a route reflector client.
                type: bool
              route_server_client:
                description:
                  - Specify a neighbor as a route server client.
                type: bool
              activate:
                description:
                  - Enable the address family for this neighbor.
                type: bool
              remove_private_as:
                description:
                  - Remove the private AS number from outbound updates.
                type: bool
              next_hop_self:
                description:
                  - Enable/disable the next hop calculation for this neighbor.
                type: bool
              next_hop_unchanged:
                description:
                  - Propagate next hop unchanged for iBGP paths to this neighbor.
                type: bool
              maximum_prefix:
                description:
                  - Maximum number of prefixes to accept from this peer.
                  - The range is from 1 to 2147483647.
                type: int
  operation:
    description:
      - Specifies the operation to be performed on the BGP process configured on the device.
      - In case of merge, the input configuration will be merged with the existing BGP configuration on the device.
      - In case of replace, if there is a diff between the existing configuration and the input configuration, the
        existing configuration will be replaced by the input configuration for every option that has the diff.
      - In case of override, all the existing BGP configuration will be removed from the device and replaced with
        the input configuration.
      - In case of delete the existing BGP configuration will be removed from the device.
    default: merge
    choices: ['merge', 'replace', 'override', 'delete']
"""

EXAMPLES = """
- name: configure global bgp as 64496
  ios_bgp:
    config:
      bgp_as: 64496
      router_id: 192.0.2.1
      log_neighbor_changes: True
      neighbors:
        - neighbor: 192.168.10.1
          remote_as: 64497
          timers:
            keepalive: 300
            holdtime: 360
            min_neighbor_holdtime: 360
        - neighbor: 198.51.100.2
          remote_as: 64498
      networks:
        - prefix: 10.0.0.0
          route_map: RMAP_1
        - prefix: 192.168.2.0
          mask: 255.255.254.0
      address_family:
        - afi: ipv4
          safi: unicast
          redistribute:
            - protocol: ospf
              id: 223
              metric: 10
    operation: merge

- name: remove bgp as 64496 from config
  ios_bgp:
    config:
      bgp_as: 64496
    operation: delete
"""

RETURN = """
commands:
  description: The list of configuration mode commands to send to the device
  returned: always
  type: list
  sample:
    - router bgp 64496
    - bgp router-id 192.0.2.1
    - bgp log-neighbor-changes
    - neighbor 192.168.10.1 remote-as 64497
    - neighbor 192.168.10.1 timers 300 360 360
    - neighbor 198.51.100.2 remote-as 64498
    - network 10.0.0.0 route-map RMAP_1
    - network 192.168.2.0 mask 255.255.254.0
    - address-family ipv4
    - redistribute ospf 223 metric 70
    - exit-address-family
"""
from ansible.module_utils._text import to_text
from ansible.module_utils.network.ios.providers.module import NetworkModule
from ansible.module_utils.network.ios.providers.cli.config.bgp.process import REDISTRIBUTE_PROTOCOLS


def main():
    """ main entry point for module execution
    """
    network_spec = {
        'prefix': dict(required=True),
        'masklen': dict(type='int'),
        'route_map': dict(),
    }

    redistribute_spec = {
        'protocol': dict(choices=REDISTRIBUTE_PROTOCOLS, required=True),
        'id': dict(),
        'metric': dict(type='int'),
        'route_map': dict(),
    }

    timer_spec = {
        'keepalive': dict(type='int', required=True),
        'holdtime': dict(type='int', required=True),
        'min_neighbor_holdtime': dict(type='int'),
    }

    neighbor_spec = {
        'neighbor': dict(required=True),
        'remote_as': dict(type='int', required=True),
        'local_as': dict(type='int'),
        'port': dict(type='int'),
        'update_source': dict(),
        'password': dict(no_log=True),
        'enabled': dict(type='bool'),
        'description': dict(),
        'ebgp_multihop': dict(type='int'),
        'timers': dict(type='dict', elements='dict', options=timer_spec),
        'peer_group': dict(),
    }

    af_neighbor_spec = {
        'neighbor': dict(required=True),
        'activate': dict(type='bool'),
        'advertisement_interval': dict(type='int'),
        'remove_private_as': dict(type='bool'),
        'next_hop_self': dict(type='bool'),
        'route_reflector_client': dict(type='bool'),
        'route_server_client': dict(type='bool'),
        'maximum_prefix': dict(type='int')
    }

    address_family_spec = {
        'afi': dict(choices=['ipv4', 'ipv6'], required=True),
        'safi': dict(choices=['flowspec', 'labeled-unicast', 'multicast', 'unicast'], default='unicast'),
        'networks': dict(type='list', elements='dict', options=network_spec),
        'redistribute': dict(type='list', elements='dict', options=redistribute_spec),
        'neighbors': dict(type='list', elements='dict', options=af_neighbor_spec),
    }

    config_spec = {
        'bgp_as': dict(type='int', required=True),
        'router_id': dict(),
        'log_neighbor_changes': dict(type='bool'),
        'neighbors': dict(type='list', elements='dict', options=neighbor_spec),
        'address_family': dict(type='list', elements='dict', options=address_family_spec),
        'networks': dict(type='list', elements='dict', options=network_spec)
    }

    argument_spec = {
        'config': dict(type='dict', elements='dict', options=config_spec),
        'operation': dict(default='merge', choices=['merge', 'replace', 'override', 'delete'])
    }

    module = NetworkModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    try:
        result = module.edit_config(config_filter='| section bgp')
    except Exception as exc:
        module.fail_json(msg=to_text(exc))

    module.exit_json(**result)


if __name__ == '__main__':
    main()