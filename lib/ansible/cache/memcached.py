# (c) 2014, Michael DeHaan <michael.dehaan@gmail.com>
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
import collections
import sys
import time

from ansible import constants as C
from ansible.cache.base import BaseCacheModule

try:
    import memcache
except ImportError:
    print 'python-memcached is required for the memcached fact cache'
    sys.exit(1)


class CacheModuleKeys(collections.MutableSet):
    """
    A set subclass that keeps track of insertion time and persists
    the set in memcached.
    """
    PREFIX = 'ansible_cache_keys'

    def __init__(self, cache, *args, **kwargs):
        self._cache = cache
        self._keyset = dict(*args, **kwargs)

    def __contains__(self, key):
        return key in self._keyset

    def __iter__(self):
        return iter(self._keyset)

    def __len__(self):
        return len(self._keyset)

    def add(self, key):
        self._keyset[key] = time.time()
        self._cache.set(self.PREFIX, self._keyset)

    def discard(self, key):
        del self._keyset[key]
        self._cache.set(self.PREFIX, self._keyset)

    def remove_by_timerange(self, s_min, s_max):
        for k in self._keyset.keys():
            t = self._keyset[k]
            if s_min < t < s_max:
                del self._keyset[k]
        self._cache.set(self.PREFIX, self._keyset)


class CacheModule(BaseCacheModule):

    def __init__(self, *args, **kwargs):
        if C.CACHE_PLUGIN_CONNECTION:
            connection = C.CACHE_PLUGIN_CONNECTION.split(',')
        else:
            connection = ['127.0.0.1:11211']

        self._timeout = C.CACHE_PLUGIN_TIMEOUT
        self._prefix = C.CACHE_PLUGIN_PREFIX
        self._cache = memcache.Client(connection, debug=0)
        self._keys = CacheModuleKeys(self._cache, self._cache.get(CacheModuleKeys.PREFIX) or [])

    def _make_key(self, key):
        return "{}{}".format(self._prefix, key)

    def _expire_keys(self):
        if self._timeout > 0:
            expiry_age = time.time() - self._timeout
        self._keys.remove_by_timerange(0, expiry_age)

    def get(self, key):
        value = self._cache.get(self._make_key(key))
        # guard against the key not being removed from the zset;
        # this could happen in cases where the timeout value is changed
        # between invocations
        if value is None:
            self.delete(key)
            raise KeyError
        return value

    def set(self, key, value):
        self._cache.set(self._make_key(key), value, time=self._timeout)
        self._keys.add(key)

    def keys(self):
        self._expire_keys()
        return list(iter(self._keys))

    def contains(self, key):
        self._expire_keys()
        return key in self._keys

    def delete(self, key):
        self._cache.delete(self._make_key(key))
        self._keys.discard(key)
