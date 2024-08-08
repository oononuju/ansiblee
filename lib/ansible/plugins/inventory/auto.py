# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
    name: auto
    author:
      - Matt Davis (@nitzmahone)
    version_added: "2.5"
    short_description: Loads and executes an inventory plugin specified in a YAML config
    description:
        - By enabling the C(auto) inventory plugin, any YAML inventory config file with a
          C(plugin) key at its root will automatically cause the named plugin to be loaded and executed with that
          config. This effectively provides automatic enabling of all installed/accessible inventory plugins.
        - To disable this behavior, remove C(auto) from the C(INVENTORY_ENABLED) config element.
"""

EXAMPLES = """
# This plugin is not intended for direct use; it is a fallback mechanism for automatic enabling of
# all installed inventory plugins.
"""

import os
import re

from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.plugins.loader import inventory_loader


class InventoryModule(BaseInventoryPlugin):

    NAME = 'auto'
    TOKEN = re.compile('@(\w+):.+')

    def verify_file(self, path):
        if os.path.exists(path):
            if not path.endswith('.yml') and not path.endswith('.yaml'):
                return False
        elif ',' in path:
            return True

        return super(InventoryModule, self).verify_file(path)

    def parse(self, inventory, loader, path, cache=True):

        if os.path.exists(path):
            config_data = loader.load_from_file(path, cache='none')
        else:
            found = self.TOKEN.match(path)
            if found:
                config_data = {'plugin': found.group(1)}
            else:
                # fallback to host_list
                config_data = {'plugin': 'host_list'}
        try:
            plugin_name = config_data.get('plugin', None)
        except AttributeError:
            plugin_name = None

        if not plugin_name:
            raise AnsibleParserError("no root 'plugin' key found, '{0}' is not a valid YAML inventory plugin config file".format(path))

        plugin = inventory_loader.get(plugin_name)

        if not plugin:
            raise AnsibleParserError("inventory config '{0}' specifies unknown plugin '{1}'".format(path, plugin_name))

        if not plugin.verify_file(path):
            raise AnsibleParserError("inventory source '{0}' could not be verified by inventory plugin '{1}'".format(path, plugin_name))

        self.display.v("Using inventory plugin '{0}' to process inventory source '{1}'".format(plugin._load_name, path))
        plugin.parse(inventory, loader, path, cache=cache)
        try:
            plugin.update_cache_if_changed()
        except AttributeError:
            pass
