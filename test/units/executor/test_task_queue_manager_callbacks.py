# (c) 2016, Steve Kuznetsov <skuznets@redhat.com>
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

import time

from multiprocessing import Value

from units.compat import unittest
from units.compat.mock import MagicMock
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.playbook import Playbook
from ansible.plugins.callback import CallbackBase

__metaclass__ = type


class TestTaskQueueManagerCallbacks(unittest.TestCase):
    def setUp(self):
        inventory = MagicMock()
        variable_manager = MagicMock()
        loader = MagicMock()
        options = MagicMock()
        passwords = []

        self._tqm = TaskQueueManager(inventory, variable_manager, loader, options, passwords)

    def tearDown(self):
        self._tqm.cleanup()

    def test_task_queue_manager_callbacks_v2_playbook_on_start(self):
        """
        Assert that no exceptions are raised when sending a Playbook
        start callback to a current callback module plugin.
        """
        register = Value('i')
        register.value = 0

        class CallbackModule(CallbackBase):
            """
            This is a callback module with the current
            method signature for `v2_playbook_on_start`.
            """
            CALLBACK_VERSION = 2.0
            CALLBACK_TYPE = 'notification'
            CALLBACK_NAME = 'current_module'

            def v2_playbook_on_start(self, playbook):
                register.value = playbook

        callback_module = CallbackModule()
        self._tqm._callback_plugins.append(callback_module)
        self._tqm._start_callback_process()
        self._tqm.send_callback('v2_playbook_on_start', 1)
        # Sleep for a short duration as send_callback operates in another process and is not synchronous with this process
        time.sleep(0.1)
        self.assertEqual(register.value, 1)

    def test_task_queue_manager_callbacks_v2_playbook_on_start_wrapped(self):
        """
        Assert that no exceptions are raised when sending a Playbook
        start callback to a wrapped current callback module plugin.
        """
        register = Value('i')
        register.value = 0

        def wrap_callback(func):
            """
            This wrapper changes the exposed argument
            names for a method from the original names
            to (*args, **kwargs). This is used in order
            to validate that wrappers which change par-
            ameter names do not break the TQM callback
            system.

            :param func: function to decorate
            :return: decorated function
            """

            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapper

        class WrappedCallbackModule(CallbackBase):
            """
            This is a callback module with the current
            method signature for `v2_playbook_on_start`
            wrapped in order to change the signature.
            """
            CALLBACK_VERSION = 2.0
            CALLBACK_TYPE = 'notification'
            CALLBACK_NAME = 'current_module'

            @wrap_callback
            def v2_playbook_on_start(self, playbook):
                register.value = playbook

        callback_module = WrappedCallbackModule()
        self._tqm._callback_plugins.append(callback_module)
        self._tqm._start_callback_process()
        self._tqm.send_callback('v2_playbook_on_start', 1)
        # Sleep for a short duration as send_callback operates in another process and is not synchronous with this process
        time.sleep(0.1)
        self.assertEqual(register.value, 1)
