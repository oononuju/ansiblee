#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.compat.tests.mock import patch
from ansible.modules.network.mlnxos import mlnxos_linkagg
from units.modules.utils import set_module_args
from .mlnxos_module import TestMlnxosModule, load_fixture


class TestMlnxosLinkaggModule(TestMlnxosModule):

    module = mlnxos_linkagg

    def setUp(self):
        super(TestMlnxosLinkaggModule, self).setUp()
        self.mock_get_config = patch.object(
            mlnxos_linkagg.MlnxosLinkAggModule,
            "_get_port_channels")
        self.get_config = self.mock_get_config.start()

        self.mock_load_config = patch(
            'ansible.module_utils.network.mlnxos.mlnxos.load_config')
        self.load_config = self.mock_load_config.start()

    def tearDown(self):
        super(TestMlnxosLinkaggModule, self).tearDown()
        self.mock_get_config.stop()
        self.mock_load_config.stop()

    def _execute_module(self, failed=False, changed=False, commands=None, sort=True):
        if failed:
            result = self.failed()
            self.assertTrue(result['failed'], result)
        else:
            result = self.changed(changed)
            self.assertEqual(result['changed'], changed, result)

        if commands is not None:
            commands_res = result.get('commands')
            if sort:
                self.assertEqual(sorted(commands), sorted(commands_res), commands_res)
            else:
                self.assertEqual(commands, commands_res, commands_res)

        return result

    def load_fixture(self, config_file):
        self.get_config.return_value = load_fixture(config_file)
        self.load_config.return_value = None

    def load_port_channel_fixture(self):
        config_file = 'mlnxos_port_channel_show.cfg'
        self.load_fixture(config_file)

    def load_mlag_port_channel_fixture(self):
        config_file = 'mlnxos_mlag_port_channel_show.cfg'
        self.load_fixture(config_file)

    def test_port_channel_no_change(self):
        set_module_args(dict(name='Po22', state='present',
                             members=['Eth1/7']))
        self.load_port_channel_fixture()
        self._execute_module(changed=False)

    def test_port_channel_remove(self):
        set_module_args(dict(name='Po22', state='absent'))
        self.load_port_channel_fixture()
        commands = ['no interface port-channel 22']
        self._execute_module(changed=True, commands=commands)

    def test_port_channel_add(self):
        set_module_args(dict(name='Po23', state='present',
                             members=['Eth1/8']))
        self.load_port_channel_fixture()
        commands = ['interface port-channel 23', 'exit',
                    'interface ethernet 1/8 channel-group 23 mode on']
        self._execute_module(changed=True, commands=commands)

    def test_port_channel_add_member(self):
        set_module_args(dict(name='Po22', state='present',
                             members=['Eth1/7', 'Eth1/8']))
        self.load_port_channel_fixture()
        commands = ['interface ethernet 1/8 channel-group 22 mode on']
        self._execute_module(changed=True, commands=commands)

    def test_port_channel_remove_member(self):
        set_module_args(dict(name='Po22', state='present'))
        self.load_port_channel_fixture()
        commands = ['interface ethernet 1/7 no channel-group']
        self._execute_module(changed=True, commands=commands)

    def test_mlag_port_channel_no_change(self):
        set_module_args(dict(name='Mpo33', state='present',
                             members=['Eth1/8']))
        self.load_mlag_port_channel_fixture()
        self._execute_module(changed=False)

    def test_mlag_port_channel_remove(self):
        set_module_args(dict(name='Mpo33', state='absent'))
        self.load_mlag_port_channel_fixture()
        commands = ['no interface mlag-port-channel 33']
        self._execute_module(changed=True, commands=commands)

    def test_mlag_port_channel_add(self):
        set_module_args(dict(name='Mpo34', state='present',
                             members=['Eth1/9']))
        self.load_mlag_port_channel_fixture()
        commands = ['interface mlag-port-channel 34', 'exit',
                    'interface ethernet 1/9 mlag-channel-group 34 mode on']
        self._execute_module(changed=True, commands=commands)

    def test_mlag_port_channel_add_member(self):
        set_module_args(dict(name='Mpo33', state='present',
                             members=['Eth1/8', 'Eth1/9']))
        self.load_mlag_port_channel_fixture()
        commands = ['interface ethernet 1/9 mlag-channel-group 33 mode on']
        self._execute_module(changed=True, commands=commands)

    def test_mlag_port_channel_remove_member(self):
        set_module_args(dict(name='Mpo33', state='present'))
        self.load_mlag_port_channel_fixture()
        commands = ['interface ethernet 1/8 no mlag-channel-group']
        self._execute_module(changed=True, commands=commands)
