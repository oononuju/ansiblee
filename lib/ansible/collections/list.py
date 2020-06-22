# (c) 2019 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from collections import defaultdict

from ansible.collections import is_collection_path
from ansible.module_utils._text import to_bytes
from ansible.module_utils.six import string_types
from ansible.utils.collection_loader import AnsibleCollectionConfig
from ansible.utils.collection_loader._collection_finder import AnsibleCollectionRef, _get_collection_name_from_path
from ansible.utils.display import Display

display = Display()


def validate_collection_path(collection_path):
    """Ensure a given path ends with 'ansible_collections'

    :param collection_path: The path that should end in 'ansible_collections'
    :return: collection_path ending in 'ansible_collections' if it does not already.
    """

    if os.path.split(collection_path)[1] != 'ansible_collections':
        return os.path.join(collection_path, 'ansible_collections')

    return collection_path


def list_valid_collection_paths(search_paths=None, warn=False):
    """
    Filter out non existing or invalid search_paths for collections
    :param search_paths: list of text-string paths, if none load default config
    :param warn: display warning if search_path does not exist
    :return: subset of original list
    """

    if search_paths is None:
        search_paths = []
    elif isinstance(search_paths, string_types):
        raise TypeError("'search_paths' is string and expected list")

    search_paths.extend(AnsibleCollectionConfig.collection_paths)

    for path in search_paths:

        b_path = to_bytes(path)
        if not os.path.exists(b_path):
            # warn for missing, but not if default
            if warn:
                display.warning("The configured collection path {0} does not exist.".format(path))
            continue

        if not os.path.isdir(b_path):
            if warn:
                display.warning("The configured collection path {0}, exists, but it is not a directory.".format(path))
            continue

        yield path


def list_collection_dirs(search_paths, coll_filter=None):
    """
    Return paths for the specific collections found in passed or configured search paths
    :param search_paths: list of text-string paths, if none load default config
    :param coll_filter: limit collections to just the specific namespace or collection, if None all are returned
    :return: list of collection directory paths
    """

    collections = defaultdict(dict)
    for path in list_valid_collection_paths(search_paths):

        b_path = to_bytes(path)
        if os.path.isdir(b_path):
            b_coll_root = to_bytes(validate_collection_path(path))

            if os.path.exists(b_coll_root) and os.path.isdir(b_coll_root):
                coll = None
                if coll_filter is None:
                    namespaces = os.listdir(b_coll_root)
                else:
                    if '.' in coll_filter:
                        (nsp, coll) = coll_filter.split('.')
                    else:
                        nsp = coll_filter
                    namespaces = [nsp]

                for ns in namespaces:
                    b_namespace_dir = os.path.join(b_coll_root, to_bytes(ns))

                    if os.path.isdir(b_namespace_dir):

                        if coll is None:
                            colls = os.listdir(b_namespace_dir)
                        else:
                            colls = [coll]

                        for collection in colls:

                            # skip dupe collections as they will be masked in execution
                            if collection not in collections[ns]:
                                b_coll = to_bytes(collection)
                                b_coll_dir = os.path.join(b_namespace_dir, b_coll)
                                if is_collection_path(b_coll_dir):
                                    collections[ns][collection] = b_coll_dir
                                    yield b_coll_dir


def get_existing_collections(search_paths=None, warn=True):
    '''
    Return a list of collections for given a path

    :param path: OS path where collections should exist

    :return: a dict with collection name: path key pairs
    '''

    collections = {}

    for b_path in list_collection_dirs(search_paths):
        cname = _get_collection_name_from_path(b_path)

        # ensure we skip masked by precedence
        if cname not in collections:
                collections[cname] = b_path

    return collections
