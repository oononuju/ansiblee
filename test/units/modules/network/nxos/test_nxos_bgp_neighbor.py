# (c) 2016 Red Hat Inc.
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from units.compat.mock import patch
from ansible.modules.network.nxos import nxos_bgp_neighbor
from .nxos_module import TestNxosModule, load_fixture, set_module_args


class TestNxosBgpNeighborModule(TestNxosModule):

    module = nxos_bgp_neighbor

    def setUp(self):
        super(TestNxosBgpNeighborModule, self).setUp()

        self.mock_load_config = patch('ansible.modules.network.nxos.nxos_bgp_neighbor.load_config')
        self.load_config = self.mock_load_config.start()

        self.mock_get_config = patch('ansible.modules.network.nxos.nxos_bgp_neighbor.get_config')
        self.get_config = self.mock_get_config.start()

    def tearDown(self):
        super(TestNxosBgpNeighborModule, self).tearDown()
        self.mock_load_config.stop()
        self.mock_get_config.stop()

    def load_fixtures(self, commands=None, device=''):
        self.get_config.return_value = load_fixture('nxos_bgp', 'config.cfg')
        self.load_config.return_value = []

    def test_nxos_bgp_neighbor_bfd_1(self):
        # None (disable) -> enable
        set_module_args(dict(asn=65535, neighbor='1.1.1.1', bfd='enable'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 1.1.1.1', 'bfd'])

        # enable -> enable (idempotence)
        set_module_args(dict(asn=65535, neighbor='1.1.1.2', bfd='enable'))
        self.execute_module(changed=False)

    def test_nxos_bgp_neighbor_bfd_2(self):
        # enable -> None (disable)
        set_module_args(dict(asn=65535, neighbor='1.1.1.2', bfd='disable'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 1.1.1.2', 'no bfd'])

        # None (disable) -> disable (idempotence)
        set_module_args(dict(asn=65535, neighbor='1.1.1.1', bfd='disable'))
        self.execute_module(changed=False)

    def test_nxos_bgp_neighbor(self):
        set_module_args(dict(asn=65535, neighbor='192.0.2.3', description='some words'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 192.0.2.3', 'description some words'])

    def test_nxos_bgp_neighbor_absent(self):
        set_module_args(dict(asn=65535, neighbor='1.1.1.1', state='absent'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'no neighbor 1.1.1.1'])

    def test_nxos_bgp_neighbor_remove_private_as(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.4', remove_private_as='all'))
        self.execute_module(changed=False, commands=[])

    def test_nxos_bgp_neighbor_remove_private_as_changed(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.4', remove_private_as='replace-as'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 3.3.3.4', 'remove-private-as replace-as'])

    # Idempotence
    def test_nxos_bgp_neighbor_local_as_no_prepend_replace_as(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.6', local_as='65523', local_as_no_prepend=True, local_as_replace_as=True))
        self.execute_module(changed=False, commands=[])

    # Remote all Local AS Attributes
    def test_nxos_bgp_neighbor_local_as_remove(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.6'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 3.3.3.6', 'no local-as 65523'])

    # Remove Subset of Local AS Attributes (ie. reapply without extras)
    def test_nxos_bgp_neighbor_local_as_changed(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.6', local_as='65523'))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 3.3.3.6', 'local-as 65523'])

    # Add Additional Extras
    def test_nxos_bgp_neighbor_local_as_no_prepend_dual_as_changed(self):
        set_module_args(dict(asn=65535, neighbor='3.3.3.6', local_as='65523', local_as_no_prepend=True, local_as_replace_as=True, local_as_dual_as=True))
        self.execute_module(changed=True, commands=['router bgp 65535', 'neighbor 3.3.3.6', 'local-as 65523 no-prepend replace-as dual-as'])
