#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.compat.tests.mock import patch
from ansible.modules.network.mlnxos import mlnxos_pfc_interface
from units.modules.utils import set_module_args
from .mlnxos_module import TestMlnxosModule, load_fixture


class TestMlnxosPfcInterfaceModule(TestMlnxosModule):

    module = mlnxos_pfc_interface

    def setUp(self):
        super(TestMlnxosPfcInterfaceModule, self).setUp()
        self._pfc_enabled = True
        self.mock_get_config = patch.object(
            mlnxos_pfc_interface.MlnxosPfcInterfaceModule,
            "_get_pfc_config")
        self.get_config = self.mock_get_config.start()

        self.mock_load_config = patch(
            'ansible.module_utils.network.mlnxos.mlnxos.load_config')
        self.load_config = self.mock_load_config.start()

    def tearDown(self):
        super(TestMlnxosPfcInterfaceModule, self).tearDown()
        self.mock_get_config.stop()
        self.mock_load_config.stop()

    def load_fixtures(self, commands=None, transport='cli'):
        if self._pfc_enabled:
            suffix = 'enabled'
        else:
            suffix = 'disabled'
        config_file = 'mlnxos_pfc_interface_%s.cfg' % suffix

        self.get_config.return_value = load_fixture(config_file)
        self.load_config.return_value = None

    def _test_pfc_if(self, if_name, enabled, changed, commands):
        state = 'enabled' if enabled else 'disabled'
        set_module_args(dict(name=if_name, state=state))
        self.execute_module(changed=changed, commands=commands)

    def _test_pfc_no_change(self, enabled):
        interfaces = ('Eth1/1', 'Eth1/1/2', 'Po1', 'Mpo2')
        changed = False
        commands = None
        for ifc in interfaces:
            self._test_pfc_if(ifc, enabled, changed, commands)

    def test_pfc_enabled_no_change(self):
        self._pfc_enabled = True
        enabled = True
        self._test_pfc_no_change(enabled)

    def test_pfc_disabled_no_change(self):
        self._pfc_enabled = False
        enabled = False
        self._test_pfc_no_change(enabled)

    def _test_pfc_change(self, enabled):
        cmd_list = [
            ('Eth1/1', 'interface ethernet 1/1'),
            ('Eth1/1/2', 'interface ethernet 1/1/2'),
            ('Po1', 'interface port-channel 1'),
            ('Mpo2', 'interface mlag-port-channel 2'),
        ]
        changed = True
        suffix = ' dcb priority-flow-control mode on force'
        if not enabled:
            suffix = ' no dcb priority-flow-control mode force'
        for (if_name, cmd) in cmd_list:
            commands = [cmd + suffix]
            self._test_pfc_if(if_name, enabled, changed, commands)

    def test_pfc_disabled_change(self):
        self._pfc_enabled = False
        enabled = True
        self._test_pfc_change(enabled)

    def test_pfc_enabled_change(self):
        self._pfc_enabled = True
        enabled = False
        self._test_pfc_change(enabled)

    def test_pfc_aggregate(self):
        self._pfc_enabled = False
        aggregate = [dict(name='Eth1/1'), dict(name='Eth1/1/2')]
        set_module_args(dict(aggregate=aggregate, state='enabled'))
        commands = [
            'interface ethernet 1/1 dcb priority-flow-control mode on force',
            'interface ethernet 1/1/2 dcb priority-flow-control mode on force']
        self.execute_module(changed=True, commands=commands)

    def test_pfc_aggregate_purge(self):
        self._pfc_enabled = True
        aggregate = [dict(name='Po1'), dict(name='Mpo2')]
        set_module_args(dict(aggregate=aggregate, state='enabled', purge=True))
        commands = [
            'interface ethernet 1/1 no dcb priority-flow-control mode force',
            'interface ethernet 1/1/2 no dcb priority-flow-control mode force']
        self.execute_module(changed=True, commands=commands)
