# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):

    # inventory cache
    DOCUMENTATION = """
options:
  cache:
    description:
      - Toggle to enable/disable the caching of the inventory's source data, requires a cache plugin setup to work.
    type: boolean
    default: False
    env:
      - name: ANSIBLE_INVENTORY_CACHE
    ini:
      - section: inventory
        key: cache
  cache_plugin:
    description:
      - Cache plugin to use for the inventory's source data.
    default: memory
    env:
      - name: ANSIBLE_INVENTORY_CACHE_PLUGIN
      - name: ANSIBLE_CACHE_PLUGIN
    ini:
      - section: inventory
        key: cache_plugin
      - section: defaults
        key: fact_caching
  _timeout:
    aliases:
      - cache_timeout:
    description:
      - Cache duration in seconds
    default: 3600
    type: integer
    env:
      - name: ANSIBLE_INVENTORY_CACHE_TIMEOUT
      - name: ANSIBLE_CACHE_PLUGIN_TIMEOUT
    ini:
      - section: inventory
        key: cache_timeout
      - section: defaults
        key: fact_caching_timeout
  _uri:
    aliases:
      - cache_connection:
    description:
      - Cache connection data or path, read cache plugin documentation for specifics.
    env:
      - name: ANSIBLE_INVENTORY_CACHE_CONNECTION
      - name: ANSIBLE_CACHE_PLUGIN_CONNECTION
    ini:
      - section: inventory
        key: cache_connection
      - section: defaults
        key: fact_caching_connection
  _prefix:
    description:
      - Prefix to use for cache plugin files/tables
    default: ansible_inventory_
    env:
      - name: ANSIBLE_INVENTORY_CACHE_PLUGIN_PREFIX
      - name: ANSIBLE_CACHE_PLUGIN_PREFIX
    ini:
      - section: inventory
        key: cache_prefix
      - section: default
        key: fact_caching_prefix
"""
