#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The facts class for nxos
this file validates each subset of facts and selectively
calls the appropriate facts gathering function
"""

from ansible.module_utils.network.nxos.argspec.facts.facts import FactsArgs
from ansible.module_utils.network.common.facts.facts import FactsBase
from ansible.module_utils.network.nxos.facts.legacy.base import Default, Legacy, Hardware, Config, Interfaces, Features
from ansible.module_utils.network.nxos.facts.lacp.lacp import LacpFacts
from ansible.module_utils.network.nxos.facts.lag_interfaces.lag_interfaces import Lag_interfacesFacts
from ansible.module_utils.network.nxos.facts.telemetry.telemetry import TelemetryFacts
from ansible.module_utils.network.nxos.facts.vlans.vlans import VlansFacts


FACT_LEGACY_SUBSETS = dict(
    default=Default,
    legacy=Legacy,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
    features=Features,
)
FACT_RESOURCE_SUBSETS = dict(
    lag_interfaces=Lag_interfacesFacts,
    telemetry=TelemetryFacts,
    vlans=VlansFacts,
    lacp=LacpFacts,
)


class Facts(FactsBase):
    """ The fact class for nxos
    """

    VALID_LEGACY_GATHER_SUBSETS = frozenset(FACT_LEGACY_SUBSETS.keys())
    VALID_RESOURCE_SUBSETS = frozenset(FACT_RESOURCE_SUBSETS.keys())

    def __init__(self, module):
        super(Facts, self).__init__(module)

    def get_facts(self, legacy_facts_type=None, resource_facts_type=None, data=None):
        """ Collect the facts for nxos
        :param legacy_facts_type: List of legacy facts types
        :param resource_facts_type: List of resource fact types
        :param data: previously collected conf
        :rtype: dict
        :return: the facts gathered
        """
        netres_choices = FactsArgs.argument_spec['gather_network_resources'].get('choices', [])
        if self.VALID_RESOURCE_SUBSETS:
            self.get_network_resources_facts(netres_choices, FACT_RESOURCE_SUBSETS, resource_facts_type, data)

        if self.VALID_LEGACY_GATHER_SUBSETS:
            self.get_network_legacy_facts(FACT_LEGACY_SUBSETS, legacy_facts_type)

        return self.ansible_facts, self._warnings
